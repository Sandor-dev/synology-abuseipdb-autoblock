# synology-abuseipdb-autoblock
Synology DSM Auto Block script to import AbuseIPDB high-confidence IP lists
usage: Copy it into your NAS
give permission with "chmod 700 /volume1/whereisthefile/block_list.sh"
run it /volume1/whereisthefile/block_list.sh

it download the abuseipdb last 1 day banned IP-s from database. Keep run every day, dont worry it will delete the ip's 10 days after (mostly theese are nonfixIP home user's infected computers/phones, etc)
