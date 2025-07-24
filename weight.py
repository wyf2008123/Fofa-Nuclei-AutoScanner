import subprocess
import os
import sys
import re

tool_path = r"C:\Users\root\Desktop\yunye\ip2domain-ip2domain_v0.2\ip2domain.py"
data_dir = r"C:\Users\root\Desktop\数据"
tmp_dir = os.path.join(data_dir, "临时")

os.makedirs(tmp_dir, exist_ok=True)


def extract_number(filename):
    match = re.match(r"^(\d+)_res\.txt$", filename)
    return int(match.group(1)) if match else float('inf')


def extract_hosts(text):
    hosts = set()
    matches = re.findall(r"https?://([a-zA-Z0-9\.\-]+(?::\d+)?)(?:/[^\s]*)?", text)
    hosts.update(f"http://{m.strip()}" for m in matches)

    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", text)
    hosts.update(f"http://{ip.strip()}" for ip in ip_matches)
    return hosts


if not os.path.isfile(tool_path):
    print(f"工具文件不存在: {tool_path}")
    sys.exit(1)

for filename in sorted(os.listdir(data_dir), key=extract_number):
    if not filename.endswith("_res.txt"):
        continue

    input_path = os.path.join(data_dir, filename)
    print(f"\n正在处理文件：{filename}")

    extracted = set()
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            extracted.update(extract_hosts(line))

    if not extracted:
        print("未提取到任何目标")
        continue

    print(f"提取到 {len(extracted)} 个唯一主机目标")

    clean_file = os.path.join(tmp_dir, f"clean_{filename}")
    with open(clean_file, "w", encoding="utf-8") as out:
        out.writelines(f"{item}\n" for item in sorted(extracted))

    cmd = [
        sys.executable,
        tool_path,
        "-f", clean_file,
        "--icp",
        "-r", "1",
        "-s", "1",
        "-T", "5"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        for line in process.stdout:
            print(line.strip())
    except subprocess.TimeoutExpired:
        print("超时：执行时间过长")
    except Exception as e:
        print(f"执行错：{e}")
