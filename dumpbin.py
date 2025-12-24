#!/usr/bin/env python3
"""
FIRMWARE BIN ADVANCED ANALYZER - DumpBin 
Este proyecto nacio para personas que son nuevas en el analisis de firmware y que buscan ya sea leer el codigo para replicar cosas manuales 
o saber que buscar durante el analisis
"""

import os
import sys
import re
import argparse
import subprocess
import hashlib
import json
import math  
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import struct
import binascii

try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''

class FirmwareAnalyzer:
    """Clase principal para análisis avanzado de firmware """
    
    # Firmas conocidas de sistemas de archivos
    FS_SIGNATURES = {
        b'\x53\xef': 'ext2/3/4',
        b'\xeb\x3c\x90': 'FAT12/16',
        b'\xeb\x58\x90': 'FAT32',
        b'\x4d\x5a': 'DOS/MBR',
        b'\x7f\x45\x4c\x46': 'ELF',
        b'\x52\x61\x72\x21': 'RAR',
        b'\x50\x4b\x03\x04': 'ZIP',
        b'\x1f\x8b': 'GZIP',
        b'\x42\x5a\x68': 'BZIP2',
        b'\xfd\x37\x7a\x58\x5a\x00': 'XZ',
        b'\x04\x22\x4d\x18': 'LZ4',
        b'\x28\xb5\x2f\xfd': 'ZSTD',
        b'\x73\x68\x73\x71': 'squashfs',
        b'\x71\x73\x68\x73': 'squashfs_be',
        b'\x5d\x00\x00': 'LZMA',
        b'\x6d\x73\x6c\x7a': 'MSLZ',
        b'\x78\x61\x72\x21': 'XAR',
        b'\x78\x01': 'Zlib',
        b'\x78\x9c': 'Zlib',
        b'\x78\xda': 'Zlib',
    }
    
    # Firmas de arquitecturas
    ARCH_SIGNATURES = {
        b'\x00\x00\x01\x20': 'ARM Cortex-M Vector Table (Little Endian)',
        b'\x20\x01\x00\x00': 'ARM Cortex-M Vector Table (Big Endian)',
        b'\x4c\x01': 'ARM little-endian',
        b'\x01\x4c': 'ARM big-endian',
        b'\x01\xf0': 'Thumb little-endian',
        b'\xf0\x01': 'Thumb big-endian',
        b'\x02\xf0': 'Thumb-2 little-endian',
        b'\xf0\x02': 'Thumb-2 big-endian',
        b'\x40\x00': 'MIPS little-endian',
        b'\x00\x40': 'MIPS big-endian',
    }
    
    # Firmas de bootloaders
    BOOTLOADER_SIGNATURES = {
        b'\xea\x00\x00\x00': 'ARM Bootloader',
        b'\xfe\xed\xfa\xce': 'Mach-O',
        b'\xce\xfa\xed\xfe': 'Mach-O LE',
        b'\xfe\xed\xfa\xcf': 'Mach-O 64',
        b'\xcf\xfa\xed\xfe': 'Mach-O 64 LE',
        b'\x7f\x45\x4c\x46': 'ELF',
        b'\x4d\x5a': 'U-Boot Legacy',
        b'\x27\x05\x19\x56': 'U-Boot',
    }
    
    # Firmas criptográficas
    CRYPTO_SIGNATURES = {
        b'\x63\x61\x6c\x67': 'Crypto Algorithm',
        b'\x6b\x65\x79\x5f': 'Key material',
        b'\x41\x45\x53': 'AES',
        b'\x44\x45\x53': 'DES',
        b'\x52\x53\x41': 'RSA',
        b'\x53\x48\x41': 'SHA',
        b'\x4d\x44\x35': 'MD5',
    }
    
    # Patrones de vulnerabilidades comunes
    VULN_PATTERNS = {
        b'password\0': 'Hardcoded password',
        b'admin\0': 'Default admin',
        b'root\0': 'Root credential',
        b'backdoor': 'Possible backdoor',
        b'debug\0': 'Debug mode',
        b'telnet\0': 'Telnet service',
        b'ftp\0': 'FTP service',
        b'/bin/sh': 'Shell access',
        b'/bin/bash': 'Bash access',
        b'system\(': 'System call',
        b'exec\(': 'Exec call',
        b'eval\(': 'Eval call',
        b'strcpy\(': 'Unsafe strcpy',
        b'strcat\(': 'Unsafe strcat',
        b'sprintf\(': 'Unsafe sprintf',
        b'gets\(': 'Unsafe gets',
        b'scanf\(': 'Unsafe scanf',
    }
    
    def __init__(self, firmware_path: str, verbose: bool = False):
        self.firmware_path = Path(firmware_path)
        self.verbose = verbose
        self.results = {
            'file_info': {},
            'hashes': {},
            'signatures': [],
            'strings': [],
            'crypto_material': [],
            'vulnerabilities': [],
            'analysis': {},
            'metadata': {}
        }
        
        if not self.firmware_path.exists():
            print(f"{Fore.RED}[!] Archivo no encontrado: {firmware_path}")
            sys.exit(1)
    
    def print_banner(self):
        """Imprime banner de la herramienta"""
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════╗
║                DUMPBIN - FIRMWARE ANALYZER               ║
║                      Advanced Firmware                   ║
║                      ****H0KM4****                       ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        Target: {self.firmware_path.name}
        Size: {self.firmware_path.stat().st_size:,} bytes
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        print(banner)
    
    def calculate_hashes(self):
        """Calcula múltiples hashes del firmware"""
        print(f"{Fore.YELLOW}[*] Calculando hashes...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        self.results['hashes'] = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest(),
            'blake2b': hashlib.blake2b(data).hexdigest(),
        }
        
        if self.verbose:
            for algo, hash_val in self.results['hashes'].items():
                print(f"    {algo.upper():10}: {hash_val}")
    
    def signature_scan(self):
        """Escanea firmas conocidas en el binario"""
        print(f"{Fore.YELLOW}[*] Escaneando firmas...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read(8192)  # Lee primeros 8KB para análisis
        
        # Escanea todas las firmas
        all_sigs = {**self.FS_SIGNATURES, **self.ARCH_SIGNATURES, 
                   **self.BOOTLOADER_SIGNATURES, **self.CRYPTO_SIGNATURES}
        
        for signature, description in all_sigs.items():
            offset = data.find(signature)
            if offset != -1:
                self.results['signatures'].append({
                    'offset': hex(offset),
                    'signature': binascii.hexlify(signature).decode(),
                    'description': description
                })
                if self.verbose:
                    print(f"    {Fore.GREEN}[+] {description:40} en offset {hex(offset)}")
    
    def calculate_entropy_corrected(self, data: bytes) -> float:
        """Calcula entropía Shannon CORRECTAMENTE"""
        if not data:
            return 0.0
        
        entropy = 0.0
        size = len(data)
        
        for x in range(256):
            count = data.count(bytes([x]))
            if count > 0:
                p_x = count / size
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def entropy_analysis(self, chunk_size=256):
        """Analiza entropía del firmware - VERSIÓN CORREGIDA"""
        print(f"{Fore.YELLOW}[*] Analizando entropía...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        entropy_results = []
        
        # Analiza en chunks
        for i in range(0, min(len(data), 65536), chunk_size):
            chunk = data[i:i+chunk_size]
            if len(chunk) == 0:
                continue
            
            # Calcula entropía CORRECTAMENTE
            entropy = self.calculate_entropy_corrected(chunk)
            
            if entropy > 7.5:  # Alta entropía (posible cifrado)
                entropy_results.append({
                    'offset': hex(i),
                    'entropy': round(entropy, 2),
                    'status': 'HIGH (posible cifrado)'
                })
            elif entropy > 6.0:  # Entropía media
                entropy_results.append({
                    'offset': hex(i),
                    'entropy': round(entropy, 2),
                    'status': 'MEDIUM'
                })
            else:
                entropy_results.append({
                    'offset': hex(i),
                    'entropy': round(entropy, 2),
                    'status': 'LOW'
                })
        
        # Solo guarda resultados significativos
        self.results['analysis']['entropy'] = [
            e for e in entropy_results 
            if e['status'] != 'LOW'
        ][:10]  # Solo primeros 10 no-LOW
    
    def extract_strings(self, min_length=4):
        """Extrae strings del firmware"""
        print(f"{Fore.YELLOW}[*] Extrayendo strings (min {min_length} chars)...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        # Patrón para extraer strings
        strings = []
        current_string = bytearray()
        
        for byte in data:
            if 32 <= byte <= 126:  # Caracteres imprimibles ASCII
                current_string.append(byte)
            else:
                if len(current_string) >= min_length:
                    try:
                        string_text = current_string.decode('ascii', errors='ignore')
                        strings.append({
                            'string': string_text,
                            'length': len(current_string)
                        })
                    except:
                        pass
                current_string = bytearray()
        
        # Filtra strings interesantes
        interesting_strings = []
        for s in strings:
            string = s['string'].lower()
            # Busca patrones interesantes
            interesting_keywords = [
                'http', 'ftp', 'ssh', 'telnet', 'serial', 'uart',
                'password', 'key', 'secret', 'token', 'auth',
                'admin', 'root', 'user', 'login',
                'debug', 'test', 'backdoor',
                'vpn', 'wan', 'lan', 'wifi', 'ssid',
                'version', 'firmware', 'boot', 'kernel',
                'ble', 'bluetooth', 'gap', 'gatt',  # Añadido BLE
                'aes', 'encrypt', 'decrypt', 'crypto',  # Añadido crypto
            ]
            
            if any(keyword in string for keyword in interesting_keywords):
                interesting_strings.append(s['string'])
        
        self.results['strings'] = interesting_strings[:100]  # Limita a 100
    
    def search_crypto_material(self):
        """Busca material criptografico"""
        print(f"{Fore.YELLOW}[*] Buscando material criptográfico...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        crypto_finds = []
        
        # Busca patrones de claves comunes
        key_patterns = [
            b'-----BEGIN RSA PRIVATE KEY-----',
            b'-----BEGIN PRIVATE KEY-----',
            b'-----BEGIN PUBLIC KEY-----',
            b'-----BEGIN CERTIFICATE-----',
            b'ssh-rsa',
            b'ssh-dss',
            b'ecdsa-sha2-',
        ]
        
        for pattern in key_patterns:
            offset = data.find(pattern)
            if offset != -1:
                crypto_finds.append({
                    'type': 'Crypto Key Material',
                    'offset': hex(offset),
                    'pattern': pattern.decode('ascii', errors='ignore')[:50]
                })
        
        # Busca IVs comunes (ej: AES IVs) - patrones hex
        import re
        hex_data = binascii.hexlify(data[:10000]).decode()  # Solo primeros 10KB
        
        # Busca posibles IVs de 16 bytes (32 chars hex)
        iv_matches = re.findall(r'[0-9a-f]{32}', hex_data, re.IGNORECASE)
        for match in iv_matches[:5]:  # Solo primeros 5
            offset = hex_data.find(match) // 2  # Convierte a offset en bytes
            crypto_finds.append({
                'type': 'Possible IV (16 bytes)',
                'offset': hex(offset),
                'value': match
            })
        
        # Busca posibles llaves AES (16, 24, 32 bytes) 
        key_matches = re.findall(r'[0-9a-f]{32,64}', hex_data, re.IGNORECASE)
        for match in key_matches[:10]:
            if len(match) in [32, 48, 64]:  # 16, 24, 32 bytes
                offset = hex_data.find(match) // 2
                crypto_finds.append({
                    'type': f'Possible AES Key ({len(match)//2} bytes)',
                    'offset': hex(offset),
                    'value': match[:32] + '...' if len(match) > 32 else match
                })
        
        self.results['crypto_material'] = crypto_finds
    
    def vulnerability_scan(self):
        """Escanea vulnerabilidades comunes"""
        print(f"{Fore.YELLOW}[*] Escaneando vulnerabilidades...")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read(1024*1024)  # Solo primeros 1MB para velocidad
        
        vulns = []
        for pattern, description in self.VULN_PATTERNS.items():
            offset = data.find(pattern)
            if offset != -1:
                vulns.append({
                    'severity': 'HIGH' if 'password' in description.lower() else 'MEDIUM',
                    'type': description,
                    'offset': hex(offset),
                    'pattern': pattern.decode('ascii', errors='ignore')
                })
        
        self.results['vulnerabilities'] = vulns
    
    def run_binwalk(self):
        """Ejecuta binwalk externamente"""
        print(f"{Fore.YELLOW}[*] Ejecutando Binwalk...")
        
        try:
            # Primero solo analisis
            result = subprocess.run(
                ['binwalk', str(self.firmware_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.results['analysis']['binwalk'] = result.stdout.split('\n')[:50]
                
                # Muestra resultados interesantes
                for line in result.stdout.split('\n'):
                    if 'DECIMAL' in line or '---' in line or any(x in line for x in ['ARM', 'AES', 'CRC', 'compressed']):
                        print(f"    {Fore.CYAN}{line}")
                
                # Extrae si hay estructuras
                if any(x in result.stdout for x in ['compressed', 'filesystem', 'data']):
                    print(f"    {Fore.GREEN}[+] Binwalk encontró estructuras - intentando extraer...")
                    
                    extract_dir = self.firmware_path.parent / f"{self.firmware_path.stem}_extracted"
                    extract_dir.mkdir(exist_ok=True)
                    
                    # Ejecuta extraccion en segundo plano
                    subprocess.Popen(
                        ['binwalk', '-e', '-M', '-C', str(extract_dir), str(self.firmware_path)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    print(f"    {Fore.GREEN}[+] Extracción iniciada en: {extract_dir}")
            else:
                self.results['analysis']['binwalk'] = ["Error ejecutando binwalk"]
                print(f"    {Fore.RED}[-] Binwalk error: {result.stderr[:100]}")
                
        except FileNotFoundError:
            self.results['analysis']['binwalk'] = ["Binwalk no instalado"]
            print(f"    {Fore.YELLOW}[!] Binwalk no encontrado. Instala con: sudo apt install binwalk")
        except Exception as e:
            self.results['analysis']['binwalk'] = [f"Error: {str(e)}"]
            print(f"    {Fore.RED}[-] Error binwalk: {str(e)}")
    
    def radare_analysis(self):
        """Ejecuta análisis básico con radare2"""
        print(f"{Fore.YELLOW}[*] Ejecutando análisis Radare2...")
        
        try:
            # Comandos básicos de radare2 - esto esta en prueba..
            cmds = [
                'aaa',  # Analizar todo
                'i',    # Información
                'iz',   # Strings
                'iS~BIN',   # Secciones (solo bin)
                'q'     # Salir
            ]
            
            cmd_str = ';'.join(cmds)
            result = subprocess.run(
                ['/home/jaiba/pentest/pacblu/radare2/build/r2sdb', '-n', '-q', '-c', cmd_str, str(self.firmware_path)], #para realizar el uso correcto de radare2 o si tienes especificamente el error de lib
#https://github.com/radareorg/radare2/issues/18828
                capture_output=True,
                text=True,
                timeout=45
            )
            
            if result.returncode == 0:
                output_lines = result.stdout.split('\n')
                self.results['analysis']['radare2'] = output_lines[:50]
                
                # Muestra info interesante
                for line in output_lines:
                    if any(x in line.lower() for x in ['arch', 'bits', 'format', 'size', 'sha1']):
                        print(f"    {Fore.CYAN}{line}")
            else:
                self.results['analysis']['radare2'] = ["Radare2 no disponible o error"]
                print(f"    {Fore.YELLOW}[!] Radare2 error: {result.stderr[:100]}")
                
        except FileNotFoundError:
            self.results['analysis']['radare2'] = ["Radare2 no instalado"]
            print(f"    {Fore.YELLOW}[!] Radare2 no encontrado. Instala con: sudo apt install radare2")
        except Exception as e:
            self.results['analysis']['radare2'] = [f"Error: {str(e)}"]
            print(f"    {Fore.RED}[-] Error radare2: {str(e)}")
    
    def exploit_check(self):
        """Verifica posibles vectores de explotación"""
        print(f"{Fore.YELLOW}[*] Verificando vectores de explotación...")
        
        exploits = []
        
        # Verifica permisos de archivo
        st = os.stat(self.firmware_path)
        if st.st_mode & 0o777 == 0o777:
            exploits.append({
                'type': 'File Permissions',
                'risk': 'HIGH',
                'description': 'Firmware con permisos 777 (world writable)'
            })
        
        # Busca shellcodes comunes
        shellcode_patterns = [
            (b'\x31\xc0\x50\x68\x2f\x2f\x73\x68', 'Linux x86 execve shellcode'),
            (b'\x33\xc0\x50\x68\x2f\x2f\x73\x68', 'Linux x86_64 execve shellcode'),
            (b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1', 'ARM shellcode'),
        ]
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read(1024*512)  # 512KB
            
            for pattern, desc in shellcode_patterns:
                if data.find(pattern) != -1:
                    exploits.append({
                        'type': 'Shellcode Detection',
                        'risk': 'CRITICAL',
                        'description': f'Posible shellcode: {desc}'
                    })
        
        # Busca BLE specific exploits
        ble_exploit_patterns = [
            (b'GAP_', 'GAP functions - posible BLE stack'),
            (b'GATT_', 'GATT functions - BLE service layer'),
            (b'SMP_', 'SMP - Security Manager Protocol'),
        ]
        
        for pattern, desc in ble_exploit_patterns:
            if data.find(pattern) != -1:
                exploits.append({
                    'type': 'BLE Stack Identified',
                    'risk': 'INFO',
                    'description': f'{desc} - posibles vectores BLE'
                })
        
        self.results['analysis']['exploits'] = exploits
    
    def generate_report(self, output_format='text'):
        """Genera reporte del análisis"""
        report = []
        
        # Información básica
        report.append(f"{Fore.CYAN}{'='*60}")
        report.append(f"REPORTE DE ANÁLISIS - {self.firmware_path.name}")
        report.append(f"{'='*60}{Style.RESET_ALL}")
        
        # Hashes
        report.append(f"\n{Fore.YELLOW}[HASHES]{Style.RESET_ALL}")
        for algo, hash_val in self.results['hashes'].items():
            report.append(f"  {algo.upper():10}: {hash_val}")
        
        # Firmas encontradas
        if self.results['signatures']:
            report.append(f"\n{Fore.YELLOW}[FIRMAS ENCONTRADAS]{Style.RESET_ALL}")
            for sig in self.results['signatures'][:10]:  # Solo primeras 10
                sig_desc = sig['description'][:35]
                report.append(f"  {sig_desc:35} @ {sig['offset']}")
        
        # Strings interesantes
        if self.results['strings']:
            report.append(f"\n{Fore.YELLOW}[STRINGS INTERESANTES]{Style.RESET_ALL}")
            for i, string in enumerate(self.results['strings'][:15], 1):
                display_str = string[:50] + '...' if len(string) > 50 else string
                report.append(f"  [{i:2}] {display_str}")
        
        # Material criptográfico
        if self.results['crypto_material']:
            report.append(f"\n{Fore.MAGENTA}[MATERIAL CRIPTOGRÁFICO]{Style.RESET_ALL}")
            for crypto in self.results['crypto_material'][:5]:
                report.append(f"  {crypto['type']:30} @ {crypto['offset']}")
                if 'value' in crypto:
                    report.append(f"    Valor: {crypto['value']}")
        
        # Vulnerabilidades
        if self.results['vulnerabilities']:
            report.append(f"\n{Fore.RED}[VULNERABILIDADES]{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                color = Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW
                report.append(f"  {color}{vuln['severity']:6} - {vuln['type']} @ {vuln['offset']}")
        
        # Exploits
        if self.results['analysis'].get('exploits'):
            report.append(f"\n{Fore.RED}[EXPLOIT CHECKS]{Style.RESET_ALL}")
            for exploit in self.results['analysis']['exploits']:
                if exploit['risk'] == 'CRITICAL':
                    risk_color = Fore.RED
                elif exploit['risk'] == 'HIGH':
                    risk_color = Fore.RED
                elif exploit['risk'] == 'MEDIUM':
                    risk_color = Fore.YELLOW
                else:
                    risk_color = Fore.CYAN
                report.append(f"  {risk_color}{exploit['risk']:8} - {exploit['type']}: {exploit['description']}")
        
        # Entropía
        if self.results['analysis'].get('entropy'):
            report.append(f"\n{Fore.YELLOW}[ANÁLISIS DE ENTROPÍA]{Style.RESET_ALL}")
            for ent in self.results['analysis']['entropy'][:5]:
                status_color = Fore.RED if 'HIGH' in ent['status'] else Fore.YELLOW
                report.append(f"  Offset {ent['offset']}: Entropía={ent['entropy']} ({status_color}{ent['status']}{Style.RESET_ALL})")
        
        # Información adicional
        report.append(f"\n{Fore.CYAN}[INFORMACIÓN ADICIONAL]{Style.RESET_ALL}")
        report.append(f"  Tamaño total: {self.firmware_path.stat().st_size:,} bytes")
        report.append(f"  Hashes calculados: {len(self.results['hashes'])}")
        report.append(f"  Strings encontrados: {len(self.results['strings'])}")
        report.append(f"  Firmas identificadas: {len(self.results['signatures'])}")
        
        # Recomendaciones específicas para BLE
        if any('BLE' in str(item) for item in self.results['strings'] + 
               [sig['description'] for sig in self.results['signatures']]):
            report.append(f"\n{Fore.CYAN}[RECOMENDACIONES BLE]{Style.RESET_ALL}")
            report.append("  1. Buscar funciones GAP/GATT en el código")
            report.append("  2. Analizar handlers de características BLE")
            report.append("  3. Buscar almacenamiento de LTK/IRK/CSRK")
            report.append("  4. Probar pairing con llaves por defecto")
        
        return '\n'.join(report)
    
    def dump_sections(self, output_dir=None):
        """Vuelca secciones interesantes del firmware"""
        if output_dir is None:
            output_dir = self.firmware_path.parent / f"{self.firmware_path.stem}_dump"
        
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        print(f"{Fore.YELLOW}[*] Volcando secciones en: {output_dir}")
        
        with open(self.firmware_path, 'rb') as f:
            data = f.read()
        
        # 1. Header (primeros 512 bytes)
        header_path = output_dir / "header_0x000.bin"
        with open(header_path, 'wb') as f:
            f.write(data[:512])
        
        # 2. Vector table ARM (si existe)
        vt_offset = data.find(b'\x00\x00\x01\x20')
        if vt_offset != -1:
            vt_path = output_dir / f"vector_table_0x{vt_offset:x}.bin"
            with open(vt_path, 'wb') as f:
                f.write(data[vt_offset:vt_offset+512])
        
        # 3. Secciones basadas en firmas
        for sig in self.results['signatures'][:5]:
            try:
                offset = int(sig['offset'], 16)
                if 0 <= offset < len(data):
                    safe_name = re.sub(r'[^\w\-_]', '_', sig['description'])[:30]
                    section_path = output_dir / f"sig_{safe_name}_0x{offset:x}.bin"
                    with open(section_path, 'wb') as f:
                        # Extrae 1KB alrededor, asegurando límites
                        start = max(0, offset - 256)
                        end = min(len(data), offset + 768)
                        f.write(data[start:end])
            except:
                continue
        
        # 4. Áreas de alta entropía (posibles llaves cifradas)
        if self.results['analysis'].get('entropy'):
            for i, ent in enumerate(self.results['analysis']['entropy'][:3]):
                try:
                    offset = int(ent['offset'], 16)
                    if 0 <= offset < len(data):
                        entropy_path = output_dir / f"high_entropy_{i}_0x{offset:x}.bin"
                        with open(entropy_path, 'wb') as f:
                            start = max(0, offset - 128)
                            end = min(len(data), offset + 384)
                            f.write(data[start:end])
                except:
                    continue
        
        return output_dir
    
    def full_analysis(self):
        """Ejecuta análisis completo """
        self.print_banner()
        self.calculate_hashes()
        self.signature_scan()
        try:
            self.entropy_analysis()
        except Exception as e:
            print(f"{Fore.RED}[!] Error en análisis de entropía: {e}")
            self.results['analysis']['entropy'] = [f"Error: {str(e)}"]
        self.extract_strings()
        self.search_crypto_material()
        self.vulnerability_scan()
        self.exploit_check()
        
        return self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='DumpBin Pro - Advanced Firmware Binary Analyzer (CORREGIDO)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s firmware.bin --info
  %(prog)s firmware.bin --dump --force
  %(prog)s firmware.bin --test --radare
  %(prog)s firmware.bin --explo --verbose
        '''
    )
    
    parser.add_argument('firmware', help='Firmware binary file to analyze')
    parser.add_argument('-i', '--info', action='store_true', help='Show file information')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump interesting sections')
    parser.add_argument('-t', '--test', action='store_true', help='Run security tests')
    parser.add_argument('-r', '--radare', action='store_true', help='Run radare2 analysis')
    parser.add_argument('-e', '--explo', action='store_true', help='Check for exploitation vectors')
    parser.add_argument('-f', '--force', action='store_true', help='Force overwrite output files')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output directory for dumps')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware):
        print(f"{Fore.RED}[!] Error: File '{args.firmware}' not found")
        sys.exit(1)
    
    # Inicializa analizador
    analyzer = FirmwareAnalyzer(args.firmware, args.verbose)
    
    # Modo info (básico)
    if args.info:
        analyzer.calculate_hashes()
        analyzer.signature_scan()
        analyzer.extract_strings()
        print(analyzer.generate_report())
    
    # Modo dump
    elif args.dump:
        output_dir = analyzer.dump_sections(args.output)
        print(f"{Fore.GREEN}[+] Sections dumped to: {output_dir}")
    
    # Modo test (completo)
    elif args.test:
        analyzer.run_binwalk()
        if args.radare:
            analyzer.radare_analysis()
        report = analyzer.full_analysis()
        print(report)
        
        if args.json:
            json_file = Path(args.firmware).with_suffix('.json')
            with open(json_file, 'w') as f:
                # Función para serializar bytes
                def bytes_to_hex(obj):
                    if isinstance(obj, bytes):
                        return binascii.hexlify(obj).decode()
                    raise TypeError
                
                json.dump(analyzer.results, f, indent=2, default=bytes_to_hex)
            print(f"{Fore.GREEN}[+] JSON report saved to: {json_file}")
    
    # Modo explo
    elif args.explo:
        analyzer.vulnerability_scan()
        analyzer.exploit_check()
        analyzer.search_crypto_material()
        
        report = analyzer.generate_report()
        print(report)
        
        # Recomendaciones de explotacion
        if analyzer.results['vulnerabilities'] or analyzer.results['analysis'].get('exploits'):
            print(f"\n{Fore.RED}[EXPLOITATION RECOMMENDATIONS]{Style.RESET_ALL}")
            print("  1. Check for buffer overflow patterns")
            print("  2. Look for command injection points")
            print("  3. Analyze crypto implementation weaknesses")
            print("  4. Search for backdoor functions")
            print("  5. Test default credentials in extracted strings")
    
    # Modo por defecto (análisis completo)
    else:
        analyzer.run_binwalk()
        report = analyzer.full_analysis()
        print(report)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
