# 项目概述 (Project Overview)
https://fofoapi.com/index
密钥：
m1ds3zalkt76y9l7cjv8fpcmfhuem6lm


<img width="938" height="941" alt="image" src="https://github.com/user-attachments/assets/df963773-928c-4729-87df-5645c7fa8e53" />


进去后抓取信息即可使用


这个开源项目包含两个 Python 脚本，旨在帮助安全研究人员和渗透测试人员自动化以下任务：

* **从 FOFA 提取目标并进行漏洞扫描**：自动从 FOFA 网络空间测绘平台获取数据，对提取出的目标进行存活检测，并使用 Nuclei 自动化扫描潜在漏洞。
* **反查 IP/URL 对应的域名并查询百度权重**：将扫描结果中的 IP 地址或 URL 反查为域名，并查询这些域名的百度权重。

These open-source Python scripts are designed to assist security researchers and penetration testers in automating the following tasks:

* **FOFA Data Extraction and Vulnerability Scanning**: Automatically retrieve data from the FOFA cyberspace mapping platform, check the liveness of extracted targets, and perform automated vulnerability scans using Nuclei.
* **Reverse IP/URL to Domain Lookup and Baidu Weight Query**: Reverse-lookup domain names corresponding to IPs or URLs found in scan results and query their Baidu (Chinese search engine) weight.

# 脚本介绍与原理 (Script Introduction & Principles)


## 脚本一：FOFA 数据提取与 Nuclei 扫描 (Script One: FOFA Data Extraction & Nuclei Scanning)
<img width="461" height="602" alt="屏幕截图 2025-08-06 122148" src="https://github.com/user-attachments/assets/4c4fe5f3-9ce3-46a0-807f-b9be204a90f9" />

* **文件名 (Filename)**: (请根据您的实际文件名填写，例如 `automation.py`)
* **功能 (Functionality)**:
    * **FOFA 数据提取**: 根据预设的 FOFA 查询语句，自动从 FOFA API 接口批量提取目标数据（如主机、IP、域名、端口、协议等），并筛选出有效的 URL。
    * **链接存活检测**: 对提取出的 URL 进行多线程存活检测，过滤掉无法访问的目标，确保后续扫描的有效性。
    * **Nuclei 漏洞扫描**: 调用 Nuclei 工具对存活目标进行自动化漏洞扫描，支持使用自定义的 `.yaml` 漏洞模板。
    * **扫描结果日志记录**: 详细记录每次 FOFA 查询、存活检测和 Nuclei 扫描的结果，包括提取数量、存活数量和发现的漏洞数量。
* **工作原理 (Working Principle)**:
    1.  脚本会遍历指定目录下的子文件夹。每个子文件夹应包含一个 `.txt` 文件（内含 FOFA 查询语句）和一个或多个 `.yaml`/`.yml` 文件（Nuclei 模板）。
    2.  读取 `.txt` 文件中的 FOFA 查询语句，通过 `requests` 库向 FOFA API 发送 POST 请求，获取匹配的数据。FOFA API 返回的数据会经过解析，提取出 `http` 或 `https` 链接。
    3.  提取出的链接会保存到一个临时文件中。
    4.  使用 `socket` 模块进行多线程的链接存活检测。通过尝试建立 TCP 连接来判断目标是否在线可达。
    5.  筛选出存活的链接后，脚本会构建 `nuclei` 命令，调用系统中的 Nuclei 程序。`subprocess` 模块用于执行外部命令，并将存活链接文件和指定的 `.yaml` 模板作为参数传递给 Nuclei。
    6.  Nuclei 的扫描结果会被保存到指定输出文件中，并且脚本会统计漏洞数量。
    7.  所有操作的进度和结果都会记录到详细的日志文件中。

* **Functionality**:
    * **FOFA Data Extraction**: Automatically extracts target data (e.g., host, IP, domain, port, protocol) in bulk from the FOFA API based on predefined FOFA queries, filtering for valid URLs.
    * **Link Liveness Check**: Performs multi-threaded liveness checks on the extracted URLs, filtering out inaccessible targets to ensure the effectiveness of subsequent scans.
    * **Nuclei Vulnerability Scanning**: Calls the Nuclei tool to perform automated vulnerability scans on live targets, supporting custom `.yaml` vulnerability templates.
    * **Scan Result Logging**: Meticulously logs the results of each FOFA query, liveness check, and Nuclei scan, including the number of extracted items, live items, and discovered vulnerabilities.
* **Working Principle**:
    1.  The script iterates through subfolders within a specified directory. Each subfolder should contain a `.txt` file (with a FOFA query) and one or more `.yaml`/`.yml` files (Nuclei templates).
    2.  It reads the FOFA query from the `.txt` file and sends a POST request to the FOFA API using the `requests` library to retrieve matching data. The data returned by the FOFA API is parsed to extract `http` or `https` links.
    3.  The extracted links are saved to a temporary file.
    4.  Multi-threaded link liveness checks are performed using the `socket` module. By attempting to establish a TCP connection, the script determines if the target is online and reachable.
    5.  After filtering for live links, the script constructs a `nuclei` command and invokes the Nuclei program on the system. The `subprocess` module is used to execute external commands, passing the live link file and the specified `.yaml` templates as arguments to Nuclei.
    6.  Nuclei's scan results are saved to a designated output file, and the script counts the number of vulnerabilities found.
    7.  The progress and results of all operations are meticulously recorded in a detailed log file.

## 脚本二：IP/URL 反查与百度权重查询 (Script Two: IP/URL Reverse Lookup & Baidu Weight Query)

* **文件名 (Filename)**: (请根据您的实际文件名填写，例如 `weight.py`)
* **功能 (Functionality)**:
    * **从扫描结果中提取主机**: 解析 Nuclei 扫描结果文件，从中提取出 IP 地址（带端口）和 URL。
    * **IP/URL 反查域名**: 利用外部工具（`weight.py`）将提取出的 IP 地址和 URL 反查为对应的域名。
    * **百度权重查询**: 对反查到的域名进行百度权重查询。
* **工作原理 (Working Principle)**:
    1.  脚本会遍历指定数据目录中所有以 `_res.txt` 结尾的 Nuclei 扫描结果文件。
    2.  对于每个结果文件，脚本会使用正则表达式从中提取出形如 `http://example.com` 或 `1.1.1.1:8080` 的主机目标。
    3.  提取出的所有唯一主机目标会写入一个临时文件中。
    4.  脚本会调用外部的 `ip2domain.py` 工具，并将临时文件作为输入。`ip2domain.py` 负责将 IP 地址或 URL 反查为域名，并可能同时查询 ICP 备案信息等。
    5.  `subprocess` 模块用于执行 `ip2domain.py` 脚本，并捕获其标准输出，实时打印处理进度和结果。目前您的脚本只打印了 `ip2domain.py` 的输出，并没有对百度权重进行实际的查询和处理逻辑。如果需要实现百度权重查询，您需要修改脚本，解析 `ip2domain.py` 的输出，或者集成一个百度权重查询的 API/库。


* **Functionality**:
    * **Host Extraction from Scan Results**: Parses Nuclei scan result files, extracting IP addresses (with ports) and URLs.
    * **IP/URL Reverse Domain Lookup**: Utilizes an external tool (`ip2domain.py`) to reverse-lookup the corresponding domain names for the extracted IP addresses and URLs.
    * **Baidu Weight Query**: Queries the Baidu weight for the reverse-looked-up domain names.
* **Working Principle**:
    1.  The script iterates through all Nuclei scan result files ending with `_res.txt` in a specified data directory.
    2.  For each result file, the script uses regular expressions to extract host targets in the form of `http://example.com` or `1.1.1.1:8080`.
    3.  All unique extracted host targets are written to a temporary file.
    4.  The script then invokes the external `ip2domain.py` tool, passing the temporary file as input. `ip2domain.py` is responsible for reverse-looking up domain names from IP addresses or URLs, and potentially querying ICP registration information.
    5.  The `subprocess` module is used to execute the `ip2domain.py` script and capture its standard output, printing the processing progress and results in real-time. Currently, your script only prints the output of `ip2domain.py` and does not include the actual querying and processing logic for Baidu weight. If you need to implement Baidu weight queries, you'll need to modify the script to parse the output of `ip2domain.py` or integrate a Baidu weight query API/library.

# 使用方法 (How to Use)

## 前提条件 (Prerequisites)

在运行脚本之前，请确保您的系统满足以下条件：

* **Python 3.x**: 确保已安装 Python 3.x。
* **Pip**: Python 包管理器。
* **Nuclei**: 漏洞扫描工具，请从 [Nuclei GitHub](https://github.com/projectdiscovery/nuclei) 下载并配置好可执行路径。
* **ip2domain**: 反查工具，确保 `ip2domain.py` 脚本在您指定的路径中。这个工具通常需要特定的环境或依赖，请查阅其项目文档。
* **FOFA API Key/Cookies**: 脚本一依赖 FOFA API 进行数据提取。您需要在脚本中配置有效的 `cookies` (`remember_token` 和 `session`)。请注意，这些 cookie 可能会过期，需要定期更新。建议考虑使用更安全的 API Key 认证方式（如果 FOFA 官方提供）。


Before running the scripts, please ensure your system meets the following requirements:

* **Python 3.x**: Ensure Python 3.x is installed.
* **Pip**: Python package manager.
* **Nuclei**: Vulnerability scanning tool. Please download and configure the executable path from [Nuclei GitHub](https://github.com/projectdiscovery/nuclei).
* **ip2domain**: Reverse lookup tool. Ensure the `ip2domain.py` script is located at your specified path. This tool usually requires a specific environment or dependencies; please consult its project documentation.
* **FOFA API Key/Cookies**: Script one relies on the FOFA API for data extraction. You need to configure valid `cookies` (`remember_token` and `session`) within the script. Please note that these cookies may expire and need to be updated periodically. Consider using a more secure API Key authentication method if officially provided by FOFA.


## 安装依赖 (Installation)

pip install requests


## 配置 (Configuration)

### 脚本一 (Script One)

1.  **FOFA Cookies**:
    打开脚本文件 (例如 `automation.py`)，找到 `search_fofa` 函数，更新 `cookies` 字典中的 `remember_token` 和 `session` 值。这些值可以从您登录 FOFA 网站后的浏览器开发者工具中获取。
    `python
    cookies = {
        "remember_token": "您的FOFA remember_token",
        "session": "您的FOFA session"
    }
2.  **FOFA 查询目录结构 (FOFA Query Directory Structure)**:
    在您的系统上创建一个目录 (例如 `C:\Users\root\Desktop\yunye\yujianwww`)，每个子文件夹代表一个 FOFA 任务。每个子文件夹内应包含：
      * 一个 `.txt` 文件：文件名不重要，内容为单行 FOFA 查询语句，例如 `domain="example.com"` 或 `title="管理系统"`。
      * 一个或多个 `.yaml`/`.yml` 文件：这是 Nuclei 的漏洞模板文件。

    └── yujianwww/
        ├── task1/
        │   ├── query1.txt
        │   └── template_xss.yaml
        ├── task2/
        │   ├── query2.txt
        │   ├── template_sqli.yaml
        │   └── template_rce.yaml
        └── ...
3.  **输出目录 (Output Directory)**:
    在脚本末尾的 `if __name__ == "__main__":` 块中，修改 `source_folder` 和 `output_folder` 变量为您实际的路径。

    if __name__ == "__main__":
        source_folder = r"C:\Users\root\Desktop\yunye\yujianwww" # 您的 FOFA 查询目录
        output_folder = r"C:\Users\root\Desktop\数据"              # 扫描结果和日志输出目录
        batch_process_fofa_queries(source_folder, output_folder)


### 脚本二 (Script Two)

1.  **ip2domain.py 路径**:
    打开脚本文件 (例如 `weight.py`)，修改 `tool_path` 变量为您的 `weight.py` 脚本的实际路径。

    tool_path = r"C:\Users\root\Desktop\yunye\ip2domain-ip2domain_v0.2\ip2domain.py" # 您的 ip2domain.py 路径
  
2.  **数据目录 (Data Directory)**:
    修改 `data_dir` 变量为脚本一的输出目录（即 Nuclei 扫描结果 `.txt` 文件所在的目录）。

    data_dir = r"C:\Users\root\Desktop\数据" # 脚本一的输出目录，包含 Nuclei 扫描结果


## 运行脚本 (Running the Scripts)

### 运行脚本一 (Running Script One)

在命令行中导航到脚本一所在的目录，然后运行：

python your_script_name_for_fofa_nuclei.py


**注意 (Note)**: 首次运行或 FOFA Cookies 过期后，脚本可能无法正常工作。请检查控制台输出，如果出现 FOFA 查询失败的信息，请更新 `cookies`。


### 运行脚本二 (Running Script Two)

在命令行中导航到脚本二所在的目录，然后运行：

python weight.py

**注意 (Note)**: 脚本二依赖于脚本一生成的 Nuclei 扫描结果文件 (`_res.txt`)。请确保在运行脚本二之前，脚本一已经成功运行并生成了结果。

# 贡献 (Contributing)

欢迎通过 Issue 或 Pull Request 为此项目做出贡献。如果您有任何功能建议、Bug 报告或代码改进，请随时提交。


Contributions to this project are welcome via Issues or Pull Requests. If you have any feature suggestions, bug reports, or code improvements, feel free to submit them.


# 许可证 (License)

本项目根据 [MIT 许可证](https://www.google.com/search?q=LICENSE) 发布。

This project is released under the [MIT License](https://www.google.com/search?q=LICENSE).


# 免责声明 (Disclaimer)

本工具仅用于学习、研究和授权的渗透测试。作者不对滥用此工具造成的任何后果负责。请确保您在使用本工具时遵守所有适用的法律法规。

This tool is intended for educational, research, and authorized penetration testing purposes only. The author is not responsible for any consequences arising from the misuse of this tool. Please ensure you comply with all applicable laws and regulations when using this tool.
