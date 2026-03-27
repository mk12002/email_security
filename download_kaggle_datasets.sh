#!/bin/bash

# Target directory for datasets
BASE_DIR=${1:-"/home/LabsKraft/new_work/datasets"}

echo "Checking for Kaggle API credentials..."
if [ ! -f ~/.kaggle/kaggle.json ]; then
    echo "ERROR: ~/.kaggle/kaggle.json is missing!"
    echo "Please insert your Kaggle API key following the instructions provided, then re-run this script."
    exit 1
fi

echo "Downloading Missing Kaggle Datasets into $BASE_DIR..."

# CEAS 2008 Spam
if [ -z "$(ls -A "$BASE_DIR"/email_content/spam/ceas2008 2>/dev/null)" ]; then
    echo "Downloading CEAS 2008 Spam..."
    ~/.local/bin/kaggle datasets download -d bayes2003/emails-for-spam-or-ham-classification -p "$BASE_DIR/email_content/spam/ceas2008/" --unzip
else
    echo "CEAS 2008 Spam already exists. Skipping."
fi

# Ling-Spam
if [ -z "$(ls -A "$BASE_DIR"/email_content/spam/ling_spam 2>/dev/null)" ]; then
    echo "Downloading Ling-Spam..."
    ~/.local/bin/kaggle datasets download -d mandygu/lingspam-dataset -p "$BASE_DIR/email_content/spam/ling_spam/" --unzip
else
    echo "Ling-Spam already exists. Skipping."
fi

# Nigerian Fraud Corpus
if [ -z "$(ls -A "$BASE_DIR"/email_content/phishing/nigerian_fraud 2>/dev/null)" ]; then
    echo "Downloading Nigerian Fraud Corpus..."
    ~/.local/bin/kaggle datasets download -d rtatman/fraudulent-email-corpus -p "$BASE_DIR/email_content/phishing/nigerian_fraud/" --unzip
else
    echo "Nigerian Fraud Corpus already exists. Skipping."
fi

# Phishing Email Dataset (Kaggle)
if [ -z "$(ls -A "$BASE_DIR"/email_content/phishing/kaggle_phishing 2>/dev/null)" ]; then
    echo "Downloading Phishing Email Dataset..."
    ~/.local/bin/kaggle datasets download -d naserabdullahalam/phishing-email-dataset -p "$BASE_DIR/email_content/phishing/kaggle_phishing/" --unzip
else
    echo "Phishing Email Dataset already exists. Skipping."
fi

# Kaggle Malicious URLs (651K URLs)
if [ ! -f "$BASE_DIR/url_dataset/malicious_phish.csv" ]; then
    echo "Downloading Kaggle Malicious URLs..."
    kaggle datasets download -d sid321axn/malicious-urls-dataset -p "$BASE_DIR/url_dataset/" --unzip
else
    echo "Kaggle Malicious URLs already exist. Skipping."
fi

# Enron
if [ ! -f "$BASE_DIR/email_content/legitimate/enron/emails.csv" ]; then
    echo "Downloading Enron Email Dataset..."
    kaggle datasets download -d wcukierski/enron-email-dataset -p "$BASE_DIR/email_content/legitimate/enron/" --unzip
else
    echo "Enron Email Dataset already exists. Skipping."
fi

echo "Kaggle Dataset downloads complete!"
