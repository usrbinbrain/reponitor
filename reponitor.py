#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ssl
import re
import json
import http.client
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

SLACK_WEBHOOK_URL = os.getenv('SWH_URL')
GH_PAT = os.getenv('GH_PAT')

class HTTPRequestException(Exception):
    def __init__(self, status_code, message="HTTP request failed"):
        super().__init__(f"{message} with status code: {status_code}")
        self.status_code = status_code

def get_latest_release(repo, gh_pat=None):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    parsed_url = urlparse(url)
    headers = {"User-Agent": "Python-http.client/3.9"}
    
    if gh_pat:
        headers['Authorization'] = f'token {gh_pat}'
    
    try:
        connection = http.client.HTTPSConnection(parsed_url.hostname)
        connection.request("GET", parsed_url.path, headers=headers)
        response = connection.getresponse()
        if response.status == 200:
            data = json.loads(response.read().decode('utf-8'))
            return data['tag_name'], data['published_at']
        elif response.status == 404:
            return None
        else:
            raise Exception(f"Failed to fetch releases: {response.status}")
    except http.client.HTTPException as e:
        raise Exception(f"HTTPException: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error: {str(e)}")
    finally:
        if 'connection' in locals():
            connection.close()

def get_advisories_info(content):
    pattern = re.compile(
        r'<a href="(?P<id>/advisories/[^"]+)"[^>]*>\s*.*?\s*</a>.*?<span class="text-bold">\s*(?P<cve>CVE-\d{4}-\d{4,7})\s*</span>.*?<relative-time datetime="(?P<date>[^"]+)"',
        re.DOTALL
    )
    current_date = datetime.now(timezone.utc)
    result = []
    for match in pattern.findall(content):
        publish_date = datetime.fromisoformat(match[2].replace("Z", "+00:00"))
        days_since_publish = (current_date - publish_date).days
        time_since_publish = (current_date - publish_date).total_seconds()
        delta = timedelta(seconds=time_since_publish)

        result.append({
            "id": match[0],
            "cve": match[1],
            "date": match[2],
            "days_since_publish": days_since_publish,
            "time_since_publish": f"{delta.days} dias, {delta.seconds // 3600} horas, {(delta.seconds % 3600) // 60} minutos, {delta.seconds % 60} segundos",
            "timestamp_since_publish": time_since_publish
        })

    return result

def filter_advisories_within_range(advisories, days=0, hours=0, minutes=0, seconds=0):
    max_seconds = timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds).total_seconds()
    filtered = [
        advisory for advisory in advisories 
        if 0 <= advisory["timestamp_since_publish"] <= max_seconds
    ]
    return filtered

def send_msg_slack(pub_repo_name, fork_repo_name, advisories, pub_release_info, fork_release_info, webhook_url):
    if fork_release_info is None:
        fork_repo_message = f"⚙*Último release de <https://github.com/{fork_repo_name}|{fork_repo_name}>:* (Release não encontrado)"
    else:
        fork_repo_message = f"⚙*Último release de <https://github.com/{fork_repo_name}|{fork_repo_name}>:* {fork_release_info[0]} - {fork_release_info[1]}"

    if not advisories:
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Nenhuma vulnerabilidade detectada no projeto <https://github.com/{pub_repo_name}|{pub_repo_name}>.*\n"
                        f"🔎*Período analisado: {DAYS} dias, {HOURS} horas, {MINUTES} minutos e {SECONDS} segundos.*\n"
                        f"⚙*Último release de <https://github.com/{pub_repo_name}|{pub_repo_name}>:* {pub_release_info[0]} - {pub_release_info[1]}\n"
                        f"{fork_repo_message}"
                    )
                }
            }
        ]
    else:
        total = len(advisories)
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Vulnerabilidades encontradas no projeto <https://github.com/{pub_repo_name}|{pub_repo_name}> via <https://github.com/advisories?query={pub_repo_name}|GitHub Advisories>.*\n"
                        f"*❌Total de vulnerabilidades: {total}*\n"
                        f"🔎*Período analisado: {DAYS} dias, {HOURS} horas, {MINUTES} minutos e {SECONDS} segundos.*\n"
                        f"⚙*Último release de <https://github.com/{pub_repo_name}|{pub_repo_name}>:* {pub_release_info[0]} - {pub_release_info[1]}\n"
                        f"{fork_repo_message}"
                    )
                }
            }
        ]
        for advisory in advisories:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*ID:* <https://github.com{advisory['id']}|{advisory['id'].split('/')[-1]}>\n"
                        f"*CVE:* <https://nvd.nist.gov/vuln/detail/{advisory['cve']}|{advisory['cve']}>\n"
                        f"*Data de publicação:* {advisory['date']}\n"
                        f"*Tempo desde a publicação:* {advisory['time_since_publish']}"
                    )
                }
            })
            blocks.append({"type": "divider"})

    parsed_url = urlparse(webhook_url)
    conn = http.client.HTTPSConnection(parsed_url.netloc)
    payload = json.dumps({
        "username": "Reponitor",
        "icon_emoji": ":warning:",
        "blocks": blocks
    })
    headers = {"Content-Type": "application/json"}
    conn.request("POST", parsed_url.path, body=payload, headers=headers)
    response = conn.getresponse()
    response_data = response.read().decode()
    print(f"Corpo da resposta: {response_data}")


def get_github_advisories(repo_name):
    try:
        url = f"https://github.com/advisories?query={repo_name}"
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            raise ValueError("Only HTTPS protocol is allowed for security reasons.")
        
        context = ssl.create_default_context()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        }
        
        connection = http.client.HTTPSConnection(parsed_url.hostname, context=context)
        path = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        
        if response.status != 200:
            raise HTTPRequestException(response.status, "Failed to fetch data from GitHub")
        content = response.read().decode('utf-8')
        return content

    except (http.client.HTTPException, ssl.SSLError) as e:
        print(f"[Error] Network-related error occurred: {e}")
    except HTTPRequestException as e:
        print(f"[Error] {e}")
    except ValueError as e:
        print(f"[Error] {e}")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
    finally:
        if 'connection' in locals() and connection:
            connection.close()

if __name__ == "__main__":
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        print("config.json file not found.")
        exit(1)
    except json.JSONDecodeError:
        print("Error decoding config.json.")
        exit(1)

    try:
        GH_PROJECTS_NAMES = config['repository_pairs']
        DAYS = config['search_range']['days']
        HOURS = config['search_range']['hours']
        MINUTES = config['search_range']['minutes']
        SECONDS = config['search_range']['seconds']
    except KeyError as e:
        print(f"Key error: {e}")
    except TypeError as e:
        print(f"Type error: {e}")

    try:
        for repo_name in GH_PROJECTS_NAMES:
            pub_repo_name = repo_name.get('public', 'default_public_value')
            fork_repo_name = repo_name.get('fork', 'default_fork_value')
            pub_release_info = get_latest_release(pub_repo_name, GH_PAT)
            fork_release_info = get_latest_release(fork_repo_name, GH_PAT)
            content = get_github_advisories(pub_repo_name)
            if content:
                gh_advisories_data = get_advisories_info(content)
                new_gh_advisories = filter_advisories_within_range(gh_advisories_data, DAYS, HOURS, MINUTES, SECONDS)
                send_msg_slack(pub_repo_name, fork_repo_name, new_gh_advisories, pub_release_info, fork_release_info, SLACK_WEBHOOK_URL)
    except KeyError as e:
        print(f"Key error: {e}")
    except TypeError as e:
        print(f"Type error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
        