#!/bin/bash

# Target directory for datasets
BASE_DIR=${1:-"/home/LabsKraft/new_work/datasets"}

echo "Creating comprehensive dataset directory structure in $BASE_DIR..."

# Content Agent
mkdir -p "$BASE_DIR/email_content/phishing/nazario"
mkdir -p "$BASE_DIR/email_content/phishing/kaggle_phishing"
mkdir -p "$BASE_DIR/email_content/phishing/nigerian_fraud"
mkdir -p "$BASE_DIR/email_content/spam/spamassassin"
mkdir -p "$BASE_DIR/email_content/spam/trec07"
mkdir -p "$BASE_DIR/email_content/spam/ceas2008"
mkdir -p "$BASE_DIR/email_content/spam/ling_spam"
mkdir -p "$BASE_DIR/email_content/legitimate/spamassassin_ham"
mkdir -p "$BASE_DIR/email_content/legitimate/enron"

# URL Agent
mkdir -p "$BASE_DIR/url_dataset/malicious"
mkdir -p "$BASE_DIR/url_dataset/benign"

# Attachment Agent
mkdir -p "$BASE_DIR/attachments/malware/ember_features"
mkdir -p "$BASE_DIR/attachments/malware/malware_samples"
mkdir -p "$BASE_DIR/attachments/malware/DikeDataset"
mkdir -p "$BASE_DIR/attachments/benign"

# Sandbox Agent
mkdir -p "$BASE_DIR/sandbox_behavior"

# Threat Intel Agent
mkdir -p "$BASE_DIR/threat_intelligence/domains"
mkdir -p "$BASE_DIR/threat_intelligence/urls"
mkdir -p "$BASE_DIR/threat_intelligence/ips"
mkdir -p "$BASE_DIR/threat_intelligence/hashes"

# User Behavior Agent
mkdir -p "$BASE_DIR/user_behavior"

echo "======================================================"
echo "          1. DIRECT DOWNLOADS (AUTOMATED)             "
echo "======================================================"

echo "Downloading SpamAssassin Dataset..."
if [ -z "$(ls -A "$BASE_DIR"/email_content/spam/spamassassin 2>/dev/null)" ]; then
    wget -q https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
    wget -q https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
    tar -xjf 20030228_easy_ham.tar.bz2
    tar -xjf 20030228_spam.tar.bz2
    mv easy_ham/* "$BASE_DIR/email_content/legitimate/spamassassin_ham/" 2>/dev/null || true
    mv spam/* "$BASE_DIR/email_content/spam/spamassassin/" 2>/dev/null || true
    rm -rf easy_ham spam *.tar.bz2
else
    echo "SpamAssassin dataset already exists. Skipping."
fi

echo "Downloading TREC 2007 Spam Corpus (~300MB)..."
if [ ! -d "$BASE_DIR/email_content/spam/trec07/data" ]; then
    wget -q -nc https://plg.uwaterloo.ca/~gvcormac/treccorpus07/trec07p.tgz
    tar -xzf trec07p.tgz
    mv trec07p/* "$BASE_DIR/email_content/spam/trec07/" 2>/dev/null || true
    rm -rf trec07p trec07p.tgz
else
    echo "TREC 2007 already exists. Skipping."
fi

echo "Downloading PhishTank URL dataset..."
if [ ! -f "$BASE_DIR/url_dataset/malicious/phishtank_urls.csv" ]; then
    wget -q -nc https://data.phishtank.com/data/online-valid.csv -O "$BASE_DIR/url_dataset/malicious/phishtank_urls.csv"
else
    echo "PhishTank URLs already exist. Skipping."
fi

echo "Downloading OpenPhish Feed..."
if [ ! -f "$BASE_DIR/url_dataset/malicious/openphish_urls.csv" ]; then
    wget -q -nc https://openphish.com/feed.txt -O "$BASE_DIR/url_dataset/malicious/openphish_urls.csv"
else
    echo "OpenPhish Feed already exists. Skipping."
fi

echo "Downloading URLhaus dataset..."
if [ ! -f "$BASE_DIR/threat_intelligence/urls/urlhaus_urls.csv" ]; then
    wget -q -nc https://urlhaus.abuse.ch/downloads/csv_online/ -O "$BASE_DIR/threat_intelligence/urls/urlhaus_urls.csv"
    cp "$BASE_DIR/threat_intelligence/urls/urlhaus_urls.csv" "$BASE_DIR/url_dataset/malicious/urlhaus_urls.csv"
else
    echo "URLhaus dataset already exists. Skipping."
fi

echo "Downloading Feodo Tracker (Botnet IPs)..."
if [ ! -f "$BASE_DIR/threat_intelligence/ips/feodotracker_ips.csv" ]; then
    wget -q -nc https://feodotracker.abuse.ch/downloads/ipblocklist.csv -O "$BASE_DIR/threat_intelligence/ips/feodotracker_ips.csv"
else
    echo "Feodo Tracker dataset already exists. Skipping."
fi

echo "Downloading ThreatFox (All IOCs)..."
if [ ! -f "$BASE_DIR/threat_intelligence/hashes/threatfox.csv" ] && [ ! -f "$BASE_DIR/threat_intelligence/hashes/full.csv" ]; then
    wget -q -nc https://threatfox.abuse.ch/export/csv/full/ -O "$BASE_DIR/threat_intelligence/hashes/threatfox_full.csv.zip"
    unzip -qo "$BASE_DIR/threat_intelligence/hashes/threatfox_full.csv.zip" -d "$BASE_DIR/threat_intelligence/hashes/"
    rm "$BASE_DIR/threat_intelligence/hashes/threatfox_full.csv.zip"
else
    echo "ThreatFox dataset already exists. Skipping."
fi

echo "Downloading MalwareBazaar Metadata (File Hashes)..."
if [ ! -f "$BASE_DIR/threat_intelligence/hashes/malwarebazaar.csv" ] && [ ! -z "$(ls -A "$BASE_DIR/threat_intelligence/hashes" 2>/dev/null)" ]; then
    echo "Hashes directory already populated. Checking if Bazaar exists..."
fi
if [ -z "$(ls -A "$BASE_DIR/threat_intelligence/hashes/full.csv" 2>/dev/null)" ]; then
   wget -q -nc https://bazaar.abuse.ch/export/csv/full/ -O "$BASE_DIR/threat_intelligence/hashes/malwarebazaar_full.csv.zip"
   unzip -qo "$BASE_DIR/threat_intelligence/hashes/malwarebazaar_full.csv.zip" -d "$BASE_DIR/threat_intelligence/hashes/"
   rm "$BASE_DIR/threat_intelligence/hashes/malwarebazaar_full.csv.zip"
fi

echo "Downloading EMBER 2018 Dataset (Warning: 1.5GB+)..."
if [ ! -f "$BASE_DIR/attachments/malware/ember_features/train_features_0.jsonl" ]; then
    # Use quiet background mode and standard wget since it's large
    wget -q -nc https://ember.elastic.co/ember_dataset_2018_2.tar.bz2 -O "$BASE_DIR/attachments/malware/ember_features/ember_2018.tar.bz2"
    tar -xjf "$BASE_DIR/attachments/malware/ember_features/ember_2018.tar.bz2" -C "$BASE_DIR/attachments/malware/ember_features/"
    rm "$BASE_DIR/attachments/malware/ember_features/ember_2018.tar.bz2"
else
    echo "EMBER 2018 already exists. Skipping."
fi

echo "Cloning DikeDataset (Benign & Malware PE Samples)..."
if [ ! -d "$BASE_DIR/attachments/malware/DikeDataset/.git" ]; then
    git clone -q https://github.com/iosifache/DikeDataset.git "$BASE_DIR/attachments/malware/DikeDataset"
else
    echo "DikeDataset already exists. Skipping."
fi

echo "Creating synthetic datasets placeholders..."
if [ ! -f "$BASE_DIR/url_dataset/benign/benign_urls.csv" ]; then
    touch "$BASE_DIR/url_dataset/benign/benign_urls.csv"
fi

if [ ! -f "$BASE_DIR/user_behavior/user_email_behavior.csv" ]; then
cat <<EOF > "$BASE_DIR/user_behavior/user_email_behavior.csv"
sender_familiarity,subject_urgency,link_count,email_type,user_clicked
1,1,2,phishing,1
0,0,1,legitimate,0
1,0,0,internal,0
0,1,3,spam,1
EOF
fi

echo "======================================================"
echo "      2. KAGGLE DATASETS (REQUIRES KAGGLE API)        "
echo "======================================================"
echo "To download these, configure Kaggle CLI (pip install kaggle), "
echo "place your kaggle.json in ~/.kaggle/, and run uncommented lines below:"
echo ""
echo ">> Content Agent (Enron: ~517K emails):"
echo "# kaggle datasets download -d wcukierski/enron-email-dataset -p '$BASE_DIR/email_content/legitimate/enron/' --unzip"
echo ""
echo ">> Content Agent (CEAS 2008 Spam):"
echo "# kaggle datasets download -d bayes2003/emails-for-spam-or-ham-classification -p '$BASE_DIR/email_content/spam/ceas2008/' --unzip"
echo ""
echo ">> Content Agent (Ling-Spam):"
echo "# kaggle datasets download -d mandygu/lingspam-dataset -p '$BASE_DIR/email_content/spam/ling_spam/' --unzip"
echo ""
echo ">> Content Agent (Nigerian Fraud Corpus):"
echo "# kaggle datasets download -d rtatman/fraudulent-email-corpus -p '$BASE_DIR/email_content/phishing/nigerian_fraud/' --unzip"
echo ""
echo ">> Content Agent (Phishing Email Dataset - IWSPA-AP 2018):"
echo "# kaggle datasets download -d naserabdullahalam/phishing-email-dataset -p '$BASE_DIR/email_content/phishing/kaggle_phishing/' --unzip"
echo ""
echo ">> URL Agent (Kaggle Malicious URLs - 651K URLs) - FIXES IMBALANCE:"
echo "# kaggle datasets download -d sid321axn/malicious-urls-dataset -p '$BASE_DIR/url_dataset/' --unzip"
echo ""
echo ">> User Behavior Agent (Phishing Susceptibility):"
echo "# kaggle datasets download -d davidgarciahz/phishing-susceptibility -p '$BASE_DIR/user_behavior/' --unzip"
echo ""

echo "======================================================"
echo "  3. MANUAL REGISTRATION REQUIRED DATASETS (API/FORM) "
echo "======================================================"
echo "These datasets require manual registration, API keys, or web forms:"
echo "1. AbuseIPDB (Threat Intel IPs): https://www.abuseipdb.com/api"
echo "2. AlienVault OTX (Threat Intel): https://otx.alienvault.com/api"
echo "3. SOREL-20M (Malware): https://github.com/sophos/SOREL-20M"
echo "4. VirusShare (Malware Samples): https://virusshare.com/"
echo "5. CICMalMem-2022 (Malware Memory): https://www.unb.ca/cic/datasets/malmem-2022.html"
echo "6. CICMalDroid-2020 (Sandbox): https://www.unb.ca/cic/datasets/maldroid-2020.html"
echo "7. CCCS-CIC-AndMal-2020 (Sandbox): https://www.unb.ca/cic/datasets/andmal2020.html"
echo "8. ISCX-URL-2016 (URLs): https://www.unb.ca/cic/datasets/url-2016.html"
echo "9. Mendeley URL Dataset: https://data.mendeley.com/datasets/72ptz43s9v/1"

echo "Dataset directory structure generation and automated downloads complete using base: $BASE_DIR"
