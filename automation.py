import os
import requests
import socket
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import threading
import sys

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

def check_links_with_retry(input_file, max_threads=100, task_name=""):
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    alive = []
    total_urls = len(urls)
    completed = 0
    last_update = time.time()

    def update_progress():
        nonlocal completed
        completed += 1
        current_time = time.time()
        if current_time - last_update > 0.1:
            progress = completed / total_urls * 100
            status = f"检测存活: {task_name[:20]:<20} | {completed}/{total_urls} ({progress:.1f}%)"
            return status
        return None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {executor.submit(is_alive, url): url for url in urls}
        for fut in as_completed(future_map):
            result = fut.result()
            if result:
                alive.append(result)
            status = update_progress()
            if status:
                yield status

    with open(input_file, "w", encoding="utf-8") as f:
        for url in alive:
            f.write(url + "\n")

    failed_file = input_file.replace(".txt", "_failed.txt")
    if os.path.exists(failed_file):
        os.remove(failed_file)

    yield f"存活检测完成: {len(alive)}/{total_urls} 存活"
    return len(alive), total_urls - len(alive)

def search_fofa(query, save_path, size=10000):
    url = "https://fofoapi.com/search"
    cookies = {
        "remember_token": "1314|2717e11732868b33cdcd3996501a6a705692593583ef9ec94392f6553ab0029fcda1e5412faa090672845f8cc138b45770bb1923bf0577b05bbdcabe3389fc17",
        "session": ".eJwlzjsOwjAMANC7ZGaIP3XiXqZyElsgQYXaMiHuThH7G947LbH5fk1z2H33S1puI81JB7AQZVZxca0QbZCWHiwWWDl7sz61xoXNpGJ1L0MxxAAxD-hkZHmI1rBcoDoABpCGhLXRS-U2ta6oOrmYoWSdlJjQtcBp0hl5-vaw1dcjzcf2-tVeu2__HxBw-nwBNCA2lg.aIiVnA.fzPLOjW0kdsMfQ-duA2aKJiSKrA"
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://fofaapi.com/index",
        "Origin": "https://fofaapi.com"
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
    template_name = os.path.basename(yaml_file)
    cmd = f'nuclei -l "{input_file}" -t "{yaml_file}" -o "{output_file}" -silent'
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        count = 0
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                count = sum(1 for _ in f if _.strip())
        return count
    except subprocess.CalledProcessError as e:
        return 0

def print_banner():
    print("\n" + "═" * 70)
    print("║" + " " * 68 + "║")
    print("║" + "        ███████╗ ██████╗ ███████╗ █████╗     ██████╗ ██████╗ ███████╗        ".center(68) + "║")
    print("║" + "        ██╔════╝██╔═══██╗██╔════╝██╔══██╗    ██╔══██╗██╔══██╗██╔════╝        ".center(68) + "║")
    print("║" + "        █████╗  ██║   ██║█████╗  ███████║    ██████╔╝██████╔╝█████╗          ".center(68) + "║")
    print("║" + "        ██╔══╝  ██║   ██║██╔══╝  ██╔══██║    ██╔═══╝ ██╔══██╗██╔══╝          ".center(68) + "║")
    print("║" + "        ██║     ╚██████╔╝███████╗██║  ██║    ██║     ██║  ██║███████╗        ".center(68) + "║")
    print("║" + "        ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚══════╝        ".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("║" + "                  FOFA 自动化漏洞扫描系统 v1.0".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("═" * 70)
    print("║" + " " * 68 + "║")
    print("║" + f"  启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(68) + "║")
    print("═" * 70 + "\n")

def format_time(seconds):
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def select_templates(all_template_info):
    clear_screen()
    print("\n" + "═" * 70)
    print("选择要使用的漏洞模板 (输入 'a' 全选, 'i' 反选, 's' 搜索, 回车确认):")
    print("═" * 70)
    folder_templates = {}
    for path, folder, name in all_template_info:
        if folder not in folder_templates:
            folder_templates[folder] = []
        folder_templates[folder].append((path, name))
    selected_status = {path: True for path, _, _ in all_template_info}

    def display_template_selector(search_term=None):
        clear_screen()
        print("\n" + "═" * 70)
        print(f"{'选择':<5} {'文件夹':<20} {'模板名称':<40}")
        print("═" * 70)
        template_index = 1
        index_map = {}
        for folder, templates in sorted(folder_templates.items()):
            print(f"【{folder}】")
            for path, name in sorted(templates, key=lambda x: x[1]):
                if search_term and search_term.lower() not in name.lower():
                    continue
                status = "✓" if selected_status[path] else " "
                print(f"  [{template_index:>2}] [{status}] {name:<40}")
                index_map[template_index] = path
                template_index += 1
        print("═" * 70)
        print("操作: 数字选择/取消, a=全选, i=反选, s=搜索, 回车=确认")
        return index_map

    index_map = display_template_selector()
    while True:
        user_input = input("> ").strip()
        if user_input == "":
            break
        if user_input.lower() == 'a':
            for path in selected_status:
                selected_status[path] = True
            index_map = display_template_selector()
            continue
        if user_input.lower() == 'i':
            for path in selected_status:
                selected_status[path] = not selected_status[path]
            index_map = display_template_selector()
            continue
        if user_input.lower().startswith('s'):
            search_term = user_input[1:].strip()
            if search_term == "":
                search_term = input("请输入搜索关键词: ").strip()
            index_map = display_template_selector(search_term)
            continue
        try:
            if '-' in user_input:
                start, end = map(int, user_input.split('-'))
                indices = range(start, end + 1)
            elif ',' in user_input:
                indices = [int(x.strip()) for x in user_input.split(',')]
            else:
                indices = [int(user_input)]
            for idx in indices:
                if idx in index_map:
                    path = index_map[idx]
                    selected_status[path] = not selected_status[path]
            index_map = display_template_selector()
        except (ValueError, IndexError):
            print("输入无效，请输入数字或范围 (如: 1, 1-5, 1,3,5)")
            time.sleep(1)
            index_map = display_template_selector()
    excluded_templates = set()
    for path, selected in selected_status.items():
        if not selected:
            excluded_templates.add(path)
    selected_count = len(selected_status) - len(excluded_templates)
    print(f"\n✅ 已选择 {selected_count}/{len(selected_status)} 个模板")
    return excluded_templates

def batch_process_fofa_queries(base_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "scan_log.txt")
    start_time = time.time()
    print_banner()
    tasks = []
    all_template_info = []
    for folder_name in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue
        txt_files = [f for f in os.listdir(folder_path)
                     if f.endswith(".txt") and not f.endswith("_res.txt") and not f.endswith("_failed.txt")]
        yaml_files = [
            os.path.join(folder_path, f)
            for f in os.listdir(folder_path)
            if f.endswith(".yaml") or f.endswith(".yml")
        ]
        for yaml_file in yaml_files:
            template_name = os.path.basename(yaml_file)
            all_template_info.append((yaml_file, folder_name, template_name))
        if not txt_files or not yaml_files:
            continue
        for txt_file in txt_files:
            tasks.append({
                "folder_path": folder_path,
                "folder_name": folder_name,
                "txt_file": txt_file,
                "yaml_files": yaml_files
            })
    if not tasks:
        print("⚠️ 未找到任何有效任务！请检查源文件夹")
        return
    excluded_templates = select_templates(all_template_info)
    print(f"\n🔍 发现 {len(tasks)} 个扫描任务")
    print(f"📁 源目录: {base_dir}")
    print(f"💾 输出目录: {output_dir}")
    print("═" * 70)
    print("开始处理任务...\n")
    pbar = tqdm(total=len(tasks), desc="总进度", unit="任务",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} 任务 [{elapsed}<{remaining}]")
    status = {"current": "准备启动", "progress": ""}
    stop_event = threading.Event()

    def status_printer():
        while not stop_event.is_set():
            current_time = time.time() - start_time
            print(f"\r🔄 状态: {status['current']:<40} | 用时: {format_time(current_time)} | {status['progress']}",
                  end="", flush=True)
            time.sleep(0.1)

    printer_thread = threading.Thread(target=status_printer, daemon=True)
    printer_thread.start()
    results = []
    for i, task in enumerate(tasks):
        folder_path = task["folder_path"]
        folder_name = task["folder_name"]
        txt_file = task["txt_file"]
        yaml_files = task["yaml_files"]
        filtered_yaml_files = [
            yaml for yaml in yaml_files
            if yaml not in excluded_templates
        ]
        if not filtered_yaml_files:
            status["current"] = f"跳过任务: {folder_name}/{txt_file} (所有模板已被排除)"
            status["progress"] = ""
            time.sleep(1)
            pbar.update(1)
            continue
        status["current"] = f"处理任务 {i + 1}/{len(tasks)}: {folder_name}/{txt_file}"
        status["progress"] = f"使用 {len(filtered_yaml_files)}/{len(yaml_files)} 个模板"
        fofa_txt = os.path.join(folder_path, txt_file)
        try:
            with open(fofa_txt, "r", encoding="utf-8") as f:
                query = f.read().strip()
            if not query:
                status["current"] = f"跳过空查询: {folder_name}/{txt_file}"
                time.sleep(1)
                pbar.update(1)
                continue
        except Exception as e:
            status["current"] = f"读取查询文件失败: {e}"
            time.sleep(1)
            pbar.update(1)
            continue
        base_name = os.path.splitext(txt_file)[0]
        output_txt = os.path.join(output_dir, f"{i + 1}_{folder_name}_{base_name}.txt")
        status["current"] = f"FOFA查询: {folder_name}/{txt_file}"
        links = search_fofa(query, output_txt)
        if not links:
            status["current"] = f"无结果: {folder_name}/{txt_file}"
            time.sleep(1)
            pbar.update(1)
            continue
        status["current"] = f"存活检测: {folder_name}/{txt_file} ({len(links)}条)"
        alive_count = 0
        total_urls = len(links)
        for progress_update in check_links_with_retry(output_txt, task_name=f"{folder_name}/{txt_file}"):
            status["progress"] = progress_update
        with open(output_txt, "r", encoding="utf-8") as f:
            alive_urls = [line.strip() for line in f if line.strip()]
            alive_count = len(alive_urls)
        total_vuln = 0
        for yaml_idx, yaml_file in enumerate(filtered_yaml_files):
            yaml_name = os.path.basename(yaml_file)
            status["current"] = f"漏洞扫描: {folder_name}/{txt_file} ({yaml_idx + 1}/{len(filtered_yaml_files)})"
            status["progress"] = f"使用模板: {yaml_name}"
            output_res = os.path.join(output_dir, f"{i + 1}_{folder_name}_{base_name}_{yaml_name}_res.txt")
            vuln_count = run_nuclei_scan(output_txt, yaml_file, output_res)
            total_vuln += vuln_count
            now = datetime.now().strftime("[%Y-%m-%d %H:%M]")
            with open(log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"{now} {os.path.basename(output_txt)} + {yaml_name} → 漏洞 {vuln_count} 个\n")
        results.append({
            "task": f"{folder_name}/{txt_file}",
            "total": len(links),
            "alive": alive_count,
            "vuln": total_vuln,
            "used_templates": len(filtered_yaml_files)
        })
        now = datetime.now().strftime("[%Y-%m-%d %H:%M]")
        with open(log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(
                f"{now} 任务 {i + 1}: {folder_name}/{txt_file} → 提取 {len(links)} 条 → 存活 {alive_count}/{len(links)} → 漏洞 {total_vuln} 个\n")
        pbar.update(1)
        status["progress"] = f"存活: {alive_count}/{len(links)} | 漏洞: {total_vuln} | 模板: {len(filtered_yaml_files)}"
        time.sleep(0.5)
    stop_event.set()
    printer_thread.join()
    print("\n\n" + "═" * 70)
    print("扫描任务汇总:")
    print("═" * 70)
    print(f"{'任务名称':<40} {'总数':>6} {'存活':>6} {'漏洞':>6} {'模板':>6}")
    print("-" * 70)
    total_links = 0
    total_alive = 0
    total_vuln = 0
    total_templates = 0
    for res in results:
        print(f"{res['task'][:38]:<40} {res['total']:>6} {res['alive']:>6} {res['vuln']:>6} {res['used_templates']:>6}")
        total_links += res['total']
        total_alive += res['alive']
        total_vuln += res['vuln']
        total_templates += res['used_templates']
    print("═" * 70)
    print(f"{'总计':<40} {total_links:>6} {total_alive:>6} {total_vuln:>6} {total_templates:>6}")
    elapsed_time = time.time() - start_time
    print("\n" + "═" * 70)
    print(f"✅ 所有任务完成! 用时: {format_time(elapsed_time)}")
    print(f"📝 日志已保存至: {log_path}")
    print("═" * 70)

if __name__ == "__main__":
    source_folder = r"C:\Users\root\Desktop\yunye\yujianwww\SQL注入"
    output_folder = r"C:\Users\root\Desktop\数据"
    batch_process_fofa_queries(source_folder, output_folder)
