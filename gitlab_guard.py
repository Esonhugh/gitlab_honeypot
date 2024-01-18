import gitlab
import json
from dns.resolver import resolve
import logging as log

logLevel = log.DEBUG

log.basicConfig(format="%(asctime)s - %(message)s", level=logLevel)

login_user_token = "glpat-_E5StxG1qxWRM4v6C2Eb"
host_url = "http://10.10.137.73:8000"

sample_audit_events = [
    {
        "id": 5014,
        "author_id": -1,
        "entity_id": 5,
        "entity_type": "User",
        "details": {
            "author_name": "An unauthenticated user",
            "author_class": "Gitlab::Audit::UnauthenticatedAuthor",
            "target_id": 5,
            "target_type": "User",
            "target_details": "[\"admin@example.com\", \"Ihw7pa@cmjqtqu5b5hog3hu1gr0tksngopcp7ow4.oast.pro\"]",
            "custom_message": "Ask for password reset",
            "ip_address": "170.64.196.57",
            "entity_path": "support-bot",
            "author_email": None
        },
        "created_at": "2024-01-17T18:42:24.480+08:00"
    },
]


def create_gitlab_client(self_url, private_token):
    gl = gitlab.Gitlab(url=self_url, private_token=private_token)
    gl.auth()
    gl.enable_debug()
    return gl


def get_audit_logs(gl):
    DEBUG = False
    if DEBUG:
        return sample_audit_events
    else:
        return gl.audit_events.list()


def white_list_email(gl):
    userlist = []
    for user in gl.users.list():
        for email in user.emails.list():
            userlist.append(email.email)
    return userlist


def email_to_hostname(email: str):
    if len(email.split("@")) != 2:
        return email
    else:
        return email.split("@")[1]


def dns_a(domain):
    try:
        resolve(domain, "A")
        return None
    except:
        return None
def dns_mx(domain):
    try:
        resolve(domain, "MX")
        return None
    except:
        return None


def check_event(event, whitelist):
    msg = event["details"].get("custom_message")
    if "Ask for password reset" in msg:
        log.debug("find password resetting request... Check")
        # password resetting
        emails = json.loads(event["details"]["target_details"])
        for email in emails:
            log.debug(f"checking email {email} is hacker")
            if email not in whitelist:
                log.debug(f"email {email} is not in the white list")
                # dangerous passowrd resetting found.

                hostname = email_to_hostname(email)
                log.debug(f"find hostname from email {hostname}")
                dns_mx(email_to_hostname(email))  # trigger payload
                dns_a(email_to_hostname(email))

                oast_json = {
                    "gitlab_event_id": event["id"],
                    "hacker_scanner_ip": event["ip_address"],
                    "hacker_email": email,
                    "hacker_oast_domain": hostname,
                    "time": event["created_at"],
                }
                # nuclei public
                if 'oast.' in hostname:
                    log.info(f"email {email} contains oast in hostname.")
                    oast_json["type"] = "nuclei"
                # burp
                elif 'oastify.com' in hostname:
                    log.info(f"email {email} contains oastify.com in hostname")
                    oast_json["type"] = "burpsuite"
                # dnslog
                elif 'dnslog' in hostname:
                    log.info(f"email {email} contains dnslog in hostname")
                    oast_json["type"] = "dnslog"
                else:
                    oast_json["type"] = "real email?"
                log.warning(f"{json.dumps(oast_json, indent=4)}")
                return oast_json


def main():
    gl = create_gitlab_client(host_url, login_user_token)
    with open("hacker.json", "w+") as f:
        while True:
            white_list_emails = white_list_email(gl)
            for event in get_audit_logs(gl):
                output = check_event(event, white_list_emails)
                if output is not None:
                    f.write(json.dumps(output) + "\n")
                else:
                    pass


if __name__ == '__main__':
    main()
