import os
import re
from typing import List, Dict, Tuple

# Encode integers as Protobuf Varint bytes.
def encode_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)

# Serialize Domain message (Domain.Type type = 1, string value = 2).
# Using Domain.Type = 2 (Domain) for wildcard/suffix matching of domains and subdomains.
def serialize_domain(domain_value: str, domain_type: int = 2) -> bytes:
    field1 = b'\x08' + encode_varint(domain_type)
    val_bytes = domain_value.encode('utf-8')
    field2 = b'\x12' + encode_varint(len(val_bytes)) + val_bytes
    return field1 + field2

# Serialize GeoSite message (string country_code = 1, repeated Domain domain = 2).
# Country code serves as the geosite category/tag (e.g. ADBLOCK).
def serialize_geosite(country_code: str, domains: List[str]) -> bytes:
    cc_bytes = country_code.upper().encode('utf-8')
    field1 = b'\x0a' + encode_varint(len(cc_bytes)) + cc_bytes
    
    domain_fields = []
    for domain in domains:
        dom_bytes = serialize_domain(domain, domain_type=2)
        domain_fields.append(b'\x12' + encode_varint(len(dom_bytes)) + dom_bytes)
        
    return field1 + b''.join(domain_fields)

# Serialize GeoSiteList message (repeated GeoSite entry = 1).
def serialize_geositelist(geosites: Dict[str, List[str]]) -> bytes:
    entry_fields = []
    for country_code, domains in geosites.items():
        gs_bytes = serialize_geosite(country_code, domains)
        entry_fields.append(b'\x0a' + encode_varint(len(gs_bytes)) + gs_bytes)
    return b''.join(entry_fields)

# Parse AdGuard Home DNS filter list to extract blockList and unblockList.
# Validates domains to filter out garbage and anomalies from source lists.
def parse_adguard_file(filepath: str) -> Tuple[List[str], List[str]]:
    block_list = []
    unblock_list = []
    if not os.path.exists(filepath):
        print(f"Warning: File not found: {filepath}")
        return block_list, unblock_list
        
    domain_pattern = re.compile(r'^[a-z0-9_.-]+$')
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('@@||') and line.endswith('^'):
                domain = line[4:-1].strip().lower()
                if domain_pattern.match(domain):
                    unblock_list.append(domain)
            elif line.startswith('||') and line.endswith('^'):
                domain = line[2:-1].strip().lower()
                if domain_pattern.match(domain):
                    block_list.append(domain)
                    
    block_list = sorted(list(set(block_list)))
    unblock_list = sorted(list(set(unblock_list)))
    return block_list, unblock_list

def main():
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')
    
    # 1. Process full version
    full_txt_path = os.path.join(rules_dir, 'adblockdns.txt')
    print(f"Parsing full rules from {full_txt_path}...")
    full_block, full_unblock = parse_adguard_file(full_txt_path)
    print(f"Full rules parsed: {len(full_block)} blocked, {len(full_unblock)} unblocked.")
    
    full_geosites = {
        'ADBLOCK': full_block,
        'ADBLOCK-UNBLOCK': full_unblock
    }
    
    full_dat_path = os.path.join(rules_dir, 'adblockgeosite.dat')
    print(f"Serializing full geosite.dat to {full_dat_path}...")
    try:
        serialized_full = serialize_geositelist(full_geosites)
        with open(full_dat_path, 'wb') as f:
            f.write(serialized_full)
        print(f"Successfully generated {full_dat_path} (Size: {len(serialized_full)} bytes)")
    except Exception as e:
        print(f"Error generating full geosite.dat: {e}")
        
    # 2. Process lite version
    lite_txt_path = os.path.join(rules_dir, 'adblockdnslite.txt')
    print(f"Parsing lite rules from {lite_txt_path}...")
    lite_block, lite_unblock = parse_adguard_file(lite_txt_path)
    print(f"Lite rules parsed: {len(lite_block)} blocked, {len(lite_unblock)} unblocked.")
    
    lite_geosites = {
        'ADBLOCK': lite_block,
        'ADBLOCK-UNBLOCK': lite_unblock
    }
    
    lite_dat_path = os.path.join(rules_dir, 'adblockgeositelite.dat')
    print(f"Serializing lite geosite.dat to {lite_dat_path}...")
    try:
        serialized_lite = serialize_geositelist(lite_geosites)
        with open(lite_dat_path, 'wb') as f:
            f.write(serialized_lite)
        print(f"Successfully generated {lite_dat_path} (Size: {len(serialized_lite)} bytes)")
    except Exception as e:
        print(f"Error generating lite geosite.dat: {e}")

if __name__ == '__main__':
    main()
