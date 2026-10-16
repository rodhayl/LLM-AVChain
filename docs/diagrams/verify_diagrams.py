#!/usr/bin/env python3
"""Check diagram artifacts without third-party Python dependencies."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
EXPECTED = {
    '01_incident_learning_overview_es': (1500, 1040),
    '02_incident_components_es': (1920, 1460),
    '03_incident_sequence_es': (1920, 1880),
}
NS = '{http://www.w3.org/2000/svg}'
report = []
for stem, size in EXPECTED.items():
    svg, png = HERE / f'{stem}.svg', HERE / f'{stem}.png'
    root = ET.fromstring(svg.read_bytes())
    assert (int(root.attrib['width']), int(root.attrib['height'])) == size
    assert root.find(NS + 'title') is not None
    assert root.find(NS + 'desc') is not None
    assert root.find('.//' + NS + 'script') is None
    assert root.find('.//' + NS + 'image') is None
    assert len(root.findall(NS + 'text')) > 25
    for element in root.iter():
        assert not any('href' in key for key in element.attrib), 'Unexpected external reference'
    data = png.read_bytes()
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    assert struct.unpack('>II', data[16:24]) == size
    bounds = subprocess.run(['inkscape', str(svg), '--query-all'], capture_output=True, text=True, check=True)
    count = 0
    for line in bounds.stdout.splitlines():
        if not line.startswith('text'):
            continue
        _, x, y, w, h = line.split(',')
        x, y, w, h = map(float, (x, y, w, h))
        assert min(x, y) >= 0, (stem, line)
        assert x + w <= size[0] and y + h <= size[1], (stem, line)
        count += 1
    assert count > 25
    report.append({'file': stem, 'dimensions': list(size), 'text_elements_within_canvas': count,
                   'svg_sha256': hashlib.sha256(svg.read_bytes()).hexdigest(),
                   'png_sha256': hashlib.sha256(data).hexdigest()})
for stem in ('02_incident_components_es', '03_incident_sequence_es'):
    text = (HERE / f'{stem}.mmd').read_text()
    assert 'KnowledgeStore' in text and 'ScopedExecutor' in text
print(json.dumps({'status': 'passed', 'checks': report}, ensure_ascii=False, indent=2))
