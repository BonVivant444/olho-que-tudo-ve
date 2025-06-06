#!/usr/bin/env python3
import asyncio
import socket
import csv
import argparse
import scapy.all as scapy
import sys

# Verifica o banner HTTP
async def verificar_banner(ip_alvo, porta):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_alvo, porta), timeout=1
        )
        try:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=1)
            banner = banner.decode(errors="ignore").strip()
            return f"Porta {porta}: ABERTA - Banner: {banner[:50]}..."
        except:
            return f"Porta {porta}: ABERTA - Serviço desconhecido"
        finally:
            writer.close()
            await writer.wait_closed()
    except:
        return None

# Detecta o sistema operacional baseado no TTL (via TCP SYN)
def detectar_os(ip_alvo):
    resposta = scapy.sr1(scapy.IP(dst=ip_alvo)/scapy.TCP(dport=80, flags="S"), timeout=1, verbose=False)
    if resposta and resposta.haslayer(scapy.IP):
        ttl = resposta.ttl
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl > 64 and ttl <= 128:
            return "Windows"
        else:
            return "Sistema desconhecido"
    return "Sem resposta"

# Escaneia uma porta TCP
async def scan_port(ip_alvo, porta, resultados):
    banner = await verificar_banner(ip_alvo, porta)
    if banner:
        print(banner)
        resultados.append(banner)

# Executa o escaneamento em paralelo
async def iniciar_scan(ip_alvo, porta_inicial, porta_final, resultados):
    tarefas = [scan_port(ip_alvo, porta, resultados) for porta in range(porta_inicial, porta_final + 1)]
    await asyncio.gather(*tarefas)

# Exporta resultados para CSV
def exportar_csv(resultados):
    with open("resultados_scan.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Resultado"])
        for resultado in resultados:
            writer.writerow([resultado])

# Parser de argumentos
def obter_parametros():
    parser = argparse.ArgumentParser(description="Scanner de portas com detecção de OS e exportação CSV.")
    parser.add_argument("ip", type=str, help="Endereço IP alvo")
    parser.add_argument("-p", "--portas", type=str, help="Intervalo de portas (ex: 1-1000)", default="1-1024")
    return parser.parse_args()

# Execução principal
if __name__ == "__main__":
    print("""
        👁️
       /   \\
      /  👁️  \\
     /   ---   \\
    /  /     \\  \\
   /  /   👁️   \\  \\
  /  /         \\  \\
 /  /           \\  \\
/  /____________\\  \\
--------------------
Scanner Que Tudo Vê
by Bon Vivant
""")

    try:
        args = obter_parametros()
        ip_alvo = args.ip
        porta_inicial, porta_final = map(int, args.portas.split('-'))

        print(f"[+] Escaneando {ip_alvo} de porta {porta_inicial} a {porta_final}...\n")

        resultados = []
        asyncio.run(iniciar_scan(ip_alvo, porta_inicial, porta_final, resultados))

        os_detectado = detectar_os(ip_alvo)
        print(f"\n[+] Sistema operacional estimado: {os_detectado}")
        resultados.append(f"Detecção de SO: {os_detectado}")

        exportar_csv(resultados)
        print("[+] Resultados exportados para 'resultados_scan.csv'.")

    except KeyboardInterrupt:
        print("\n[!] Execução interrompida pelo usuário.")
        sys.exit()
    except Exception as e:
        print(f"[Erro] {e}")
        sys.exit(1)
