#!/bin/bash

echo "Creating dataset directory structure..."

mkdir -p datasets/email_content/phishing/nazario
mkdir -p datasets/email_content/spam/spamassassin
mkdir -p datasets/email_content/legitimate/spamassassin_ham
mkdir -p datasets/email_content/legitimate/enron

mkdir -p datasets/url_dataset/malicious
mkdir -p datasets/url_dataset/benign

mkdir -p datasets/attachments/malware/ember_features
mkdir -p datasets/attachments/malware/malware_samples
mkdir -p datasets/attachments/benign

mkdir -p datasets/sandbox_behavior

mkdir -p datasets/threat_intelligence/domains
mkdir -p datasets/threat_intelligence/urls
mkdir -p datasets/threat_intelligence/ips

mkdir -p datasets/user_behavior


echo "Downloading SpamAssassin Dataset..."

wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
wget https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2

tar -xjf 20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2

mv easy_ham/* datasets/email_content/legitimate/spamassassin_ham/
mv spam/* datasets/email_content/spam/spamassassin/

rm -rf easy_ham spam *.tar.bz2


echo "Downloading PhishTank URL dataset..."

wget https://data.phishtank.com/data/online-valid.csv -O datasets/url_dataset/malicious/phishtank_urls.csv


echo "Downloading OpenPhish Feed..."

wget https://openphish.com/feed.txt -O datasets/url_dataset/malicious/openphish_urls.csv


echo "Downloading URLHaus dataset..."

wget https://urlhaus.abuse.ch/downloads/csv/ -O datasets/threat_intelligence/urls/urlhaus_urls.csv


echo "Creating placeholder for benign URLs..."

touch datasets/url_dataset/benign/benign_urls.csv


echo "Creating placeholder user behavior dataset..."

cat <<EOF > datasets/user_behavior/user_email_behavior.csv
sender_familiarity,subject_urgency,link_count,email_type,user_clicked
1,1,2,phishing,1
0,0,1,legitimate,0
1,0,0,internal,0
0,1,3,spam,1
EOF


echo "Dataset setup complete."

echo "Manual downloads still required for:"
echo "1. Nazario phishing corpus"
echo "2. Enron email dataset"
echo "3. EMBER malware dataset"
echo "4. MalwareBazaar samples"
echo "5. Cuckoo sandbox logs"
echo "6. AbuseIPDB IP dataset"
