import os
import re
import argparse
from typing import List, Dict, Tuple

class ProtobufEncoder:
    """Provides pure-Python serialization to Protobuf wire format."""
    
    @staticmethod
    def encode_varint(value: int) -> bytes:
        out = bytearray()
        while value >= 0x80:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value & 0x7F)
        return bytes(out)

    @classmethod
    def serialize_domain(cls, value: str, domain_type: int = 2) -> bytes:
        # Domain.Type = 2 (RootDomain) matches the domain and its subdomains in xray-core.
        field1 = b'\x08' + cls.encode_varint(domain_type)
        val_bytes = value.encode('utf-8')
        field2 = b'\x12' + cls.encode_varint(len(val_bytes)) + val_bytes
        return field1 + field2

    @classmethod
    def serialize_geosite(cls, country_code: str, domains: List[str]) -> bytes:
        cc_bytes = country_code.upper().encode('utf-8')
        field1 = b'\x0a' + cls.encode_varint(len(cc_bytes)) + cc_bytes
        
        domain_fields = []
        for domain in domains:
            dom_bytes = cls.serialize_domain(domain)
            domain_fields.append(b'\x12' + cls.encode_varint(len(dom_bytes)) + dom_bytes)
            
        return field1 + b''.join(domain_fields)

    @classmethod
    def serialize_geositelist(cls, geosites: Dict[str, List[str]]) -> bytes:
        entry_fields = []
        for country_code, domains in geosites.items():
            gs_bytes = cls.serialize_geosite(country_code, domains)
            entry_fields.append(b'\x0a' + cls.encode_varint(len(gs_bytes)) + gs_bytes)
        return b''.join(entry_fields)


class AdGuardParser:
    """Parses AdGuard filter syntax to extract normalized block/unblock domain rules."""
    
    def __init__(self):
        self.domain_pattern = re.compile(r'^[a-z0-9_.-]+$')

    def parse_file(self, filepath: str) -> Tuple[List[str], List[str]]:
        block_list = []
        unblock_list = []
        if not os.path.exists(filepath):
            print(f"Warning: File not found: {filepath}")
            return block_list, unblock_list
            
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('@@||') and line.endswith('^'):
                    domain = line[4:-1].strip().lower()
                    if self.domain_pattern.match(domain):
                        unblock_list.append(domain)
                elif line.startswith('||') and line.endswith('^'):
                    domain = line[2:-1].strip().lower()
                    if self.domain_pattern.match(domain):
                        block_list.append(domain)
                        
        return sorted(list(set(block_list))), sorted(list(set(unblock_list)))


class GeositeCompiler:
    """Orchestrates parsing of text rules and compilation to geosite.dat files."""
    
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.parser = AdGuardParser()

    def compile(self, input_filename: str, output_filename: str):
        input_path = os.path.join(self.rules_dir, input_filename)
        output_path = os.path.join(self.rules_dir, output_filename)
        
        print(f"Parsing rules from {input_path}...")
        blocked, unblocked = self.parser.parse_file(input_path)
        print(f"Parsed: {len(blocked)} blocked, {len(unblocked)} unblocked.")
        
        geosites = {
            'ADBLOCK': blocked,
            'ADBLOCK-UNBLOCK': unblocked
        }
        
        print(f"Serializing geosite to {output_path}...")
        try:
            serialized = ProtobufEncoder.serialize_geositelist(geosites)
            with open(output_path, 'wb') as f:
                f.write(serialized)
            print(f"Generated {output_path} ({len(serialized)} bytes)")
        except Exception as e:
            print(f"Error compiling {output_filename}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Compile AdGuard txt filters to xray-core geosite.dat.")
    parser.add_argument("--rules-dir", help="Directory containing source rule files and target outputs")
    args = parser.parse_args()

    if args.rules_dir:
        rules_dir = args.rules_dir
    else:
        cwd_rules = os.path.join(os.getcwd(), 'rules')
        if os.path.exists(cwd_rules):
            rules_dir = cwd_rules
        else:
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rules')

    compiler = GeositeCompiler(rules_dir)
    compiler.compile('adblockdns.txt', 'adblockgeosite.dat')
    compiler.compile('adblockdnslite.txt', 'adblockgeositelite.dat')

if __name__ == '__main__':
    main()
