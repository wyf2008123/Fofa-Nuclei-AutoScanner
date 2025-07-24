import os
import requests
import socket
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_alive(url, timeout=5, retries=2):
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    for _ in range(retries + 1):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return url
        except:
            continue
    return None

def check_links_with_retry(input_file, max_threads=100):
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    alive = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {executor.submit(is_alive, url): url for url in urls}
        for fut in as_completed(future_map):
            result = fut.result()
            if result:
                alive.append(result)
    with open(input_file, "w", encoding="utf-8") as f:
        for url in alive:
            f.write(url + "\n")
    failed_file = input_file.replace(".txt", "_failed.txt")
    if os.path.exists(failed_file):
        os.remove(failed_file)
    return len(alive), len(urls) - len(alive)

def search_fofa(query, save_path, size=10000):
    url = "https://fofoapi.com/search"
    cookies = {
        "remember_token": "1314|2717e11732868b33cdcd3996501a6a705692593583ef9ec94392f6553ab0029fcda1e5412faa090672845f8cc138b45770bb1923bf0577b05bbdcabe3389fc17",
        "session": ".eJwlzjsOwjAMANC7ZGaIP3XiXqZyElsgQYXaMiHuThH7G947LbH5fk1z2H33S1puI81JB7AQZVZxca0QbZCWHiwWWDl7sz61xoXNpGJ1L0MxxAAxD-hkZHmI1rBcoDoABpCGhLXRS-U2ta6oOrmYoWSdlJjQtcBp0hl5-vaw1dcjzcf2-tVeu2__HxBw-nwBNCA2lg.aH8vNg.iXhAj_qVR1Oud-m_nUY3AG-l8q4"
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://fofoapi.com/index",
        "Origin": "https://fofoapi.com"
    }
    payload = {
        'query': query,
        'fields[]': [
            'host', 'ip', 'domain', 'port', 'protocol',
            'server', 'link', 'certs_subject_org', 'certs_subject_cn'
        ],
        'size': str(size)
    }
    try:
        res = requests.post(url, data=payload, headers=headers, cookies=cookies)
        data = res.json()
        if 'results' not in data or not data['results']:
            return []
        links = []
        for item in data['results']:
            if len(item) > 6 and isinstance(item[6], str) and item[6].startswith("http"):
                links.append(item[6])
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            for link in links:
                f.write(link.strip() + "\n")
        return links
    except Exception as e:
        print(f"FOFA 查询失败: {e}")
        return []

def run_nuclei_scan(input_file, yaml_file, output_file):
    if not os.path.isfile(yaml_file):
        print(f"模板不存在: {yaml_file}")
        return 0
    cmd = f'nuclei -l "{input_file}" -t "{yaml_file}" -o "{output_file}" -silent'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"扫描完成: {output_file}")
        count = 0
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            count = sum(1 for _ in f if _.strip())
        return count
    except subprocess.CalledProcessError:
        print(f"扫描失败: {input_file}")
        return 0

def write_log(log_path, line):
    now = datetime.now().strftime("[%Y-%m-%d %H:%M]")
    with open(log_path, "a", encoding="utf-8", errors="replace") as f:
        f.write(f"{now} {line}\n")

def batch_process_fofa_queries(base_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "log.txt")
    count = 0

    for folder_name in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        fofa_txt = None
        yaml_files = []

        for file in os.listdir(folder_path):
            if file.endswith(".txt") and not file.endswith("_res.txt"):
                fofa_txt = os.path.join(folder_path, file)
            elif file.endswith(".yaml") or file.endswith(".yml"):
                yaml_files.append(os.path.join(folder_path, file))

        if not fofa_txt or not yaml_files:
            continue

        try:
            with open(fofa_txt, "r", encoding="utf-8") as f:
                query = f.read().strip()
            if not query:
                continue
        except:
            continue

        count += 1
        output_txt = os.path.join(output_dir, f"{count}.txt")
        links = search_fofa(query, output_txt)
        if not links:
            print(f"[{count}] 无结果")
            continue

        print(f"提取 {len(links)} 条: {os.path.basename(output_txt)}")
        print("检测存活...")
        alive, failed = check_links_with_retry(output_txt)
        print(f"存活 {alive} / {alive + failed}")

        total_vuln = 0
        for yaml_file in yaml_files:
            yaml_name = os.path.basename(yaml_file)
            output_res = os.path.join(output_dir, f"{count}_{yaml_name}_res.txt")
            vuln_count = run_nuclei_scan(output_txt, yaml_file, output_res)
            total_vuln += vuln_count
            write_log(log_path, f"{count}.txt + {yaml_name} → 漏洞 {vuln_count} 个")

        write_log(log_path, f"提取 {len(links)} 条 → {count}.txt 存活 {alive}/{alive + failed} 漏洞合计 {total_vuln} 个")

    print(f"完成 {count} 个任务，日志: {log_path}")

if __name__ == "__main__":
    source_folder = r"C:\Users\root\Desktop\yunye\yujianwww"
    output_folder = r"C:\Users\root\Desktop\数据"
    batch_process_fofa_queries(source_folder, output_folder)
