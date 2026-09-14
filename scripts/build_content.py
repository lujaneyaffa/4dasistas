#!/usr/bin/env python3
"""
Build the aggregate data/*.json files from per-item CMS content folders.

Reads:   data/calendar/<slug>.json   (each has a "section" field)
         data/resources/<slug>.json  (each has a "category" field)
Writes:  data/sports.json, dayactivities.json, gatherings.json, trips.json,
         mosquegatherings.json, supportprograms.json, resources.json

Also auto-fills `tag` with the event title for Activities/Functions items
that have no tag, so editors never need to maintain tags manually.

Fails the build (non-zero exit) if two files share the same "id" --
that's what let "Taste of Mississauga" end up duplicated under both
Functions and Knowledge (mnn-taste-of-mississauga-sept5-6-2026.json and
...-2.json, filed under different sections) without anyone noticing
until it was live. One canonical file per id, always.

Run on every build:  python3 scripts/build_content.py
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, 'data')
CAL_DIR = os.path.join(DATA, 'calendar')
RES_DIR = os.path.join(DATA, 'resources')

# section -> legacy aggregate filename (what the website + calendar read)
SECTION_FILES = {
    'sports': 'sports.json',
    'activities': 'dayactivities.json',
    'functions': 'gatherings.json',
    'trips': 'trips.json',
    'mosqueprograms': 'mosquegatherings.json',
    'supportprograms': 'supportprograms.json',
}

AUTO_TAG_SECTIONS = {'activities', 'functions'}


def load_folder(folder):
    """Returns (items, id_to_filenames) -- the second dict is only used to
    report exactly which files collide when ids clash."""
    if not os.path.isdir(folder):
        return [], {}
    items = []
    id_to_filenames = {}
    for name in sorted(os.listdir(folder)):
        if not name.endswith('.json'):
            continue
        with open(os.path.join(folder, name), encoding='utf-8') as fh:
            item = json.load(fh)
        # Keep the item's existing id when present (migrated content); fall
        # back to the filename stem so brand-new CMS entries get one.
        if not item.get('id'):
            item['id'] = os.path.splitext(name)[0]
        id_to_filenames.setdefault(item['id'], []).append(name)
        items.append(item)
    return items, id_to_filenames


def check_no_duplicate_ids(folder_label, id_to_filenames):
    dupes = {i: files for i, files in id_to_filenames.items() if len(files) > 1}
    if not dupes:
        return
    print(f'ERROR: duplicate ids found in {folder_label} -- each id must come '
          f'from exactly one file, or the same event/resource can end up '
          f'shown twice with conflicting data (this is how "Taste of '
          f'Mississauga" got filed under both Functions and Knowledge):')
    for item_id, files in dupes.items():
        print(f'  {item_id!r} is defined in: {", ".join(files)}')
    print('Delete or merge the extra file(s), then re-run the build.')
    sys.exit(1)


def main():
    cal_items, cal_ids = load_folder(CAL_DIR)
    check_no_duplicate_ids('data/calendar/', cal_ids)

    buckets = {sec: [] for sec in SECTION_FILES}
    for item in cal_items:
        sec = item.get('section')
        if sec not in buckets:
            print(f'WARNING: unknown section {sec!r} on {item.get("id")}')
            continue
        if sec in AUTO_TAG_SECTIONS and not item.get('tag'):
            item['tag'] = item.get('title') or ''
        if not (item.get('days') or item.get('eventDate') or item.get('calDate')):
            print(f'WARNING: {item.get("id")!r} ("{item.get("title")}") has no days, '
                  f'eventDate, or calDate — it will never appear on the calendar.')
        buckets[sec].append(item)

    for sec, fname in SECTION_FILES.items():
        items = sorted(buckets[sec], key=lambda i: str(i.get('id')))
        with open(os.path.join(DATA, fname), 'w', encoding='utf-8') as fh:
            json.dump({'items': items}, fh, indent=2, ensure_ascii=False)
            fh.write('\n')
        print(f'{fname}: {len(items)} items')

    res_items, res_ids = load_folder(RES_DIR)
    check_no_duplicate_ids('data/resources/', res_ids)
    res_items.sort(key=lambda i: str(i.get('id')))
    with open(os.path.join(DATA, 'resources.json'), 'w', encoding='utf-8') as fh:
        json.dump({'items': res_items}, fh, indent=2, ensure_ascii=False)
        fh.write('\n')
    print(f'resources.json: {len(res_items)} items')


if __name__ == '__main__':
    main()
