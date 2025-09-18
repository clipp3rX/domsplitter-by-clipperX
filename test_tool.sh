#!/bin/bash

# Test script for Domain Splitter Advanced
echo "====================================================="
echo "  Domain Splitter Advanced - Test Script"
echo "====================================================="

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Failed to activate virtual environment. Continuing without it..."
    fi
fi

# Create test directory
mkdir -p test_results

# Basic test
echo -e "\n\033[1;34m[TEST 1] Basic domain analysis\033[0m"
python domain_splitter_advanced.py sample_domains.txt -o test_results/basic_domains.txt -d test_results/basic_dead.txt --output-dir test_results

# Check alive test
echo -e "\n\033[1;34m[TEST 2] Check alive domains\033[0m"
python domain_splitter_advanced.py sample_domains.txt -a -o test_results/alive_domains.txt -d test_results/alive_dead.txt --output-dir test_results

# DNS test
echo -e "\n\033[1;34m[TEST 3] DNS record analysis\033[0m"
python domain_splitter_advanced.py sample_domains.txt --dns -o test_results/dns_domains.txt -d test_results/dns_dead.txt --output-dir test_results --json --json-file test_results/dns_results.json

# SSL test
echo -e "\n\033[1;34m[TEST 4] SSL certificate analysis\033[0m"
python domain_splitter_advanced.py sample_domains.txt -a --ssl -o test_results/ssl_domains.txt -d test_results/ssl_dead.txt --output-dir test_results --json --json-file test_results/ssl_results.json

# HTML report test
echo -e "\n\033[1;34m[TEST 5] HTML report generation\033[0m"
python domain_splitter_advanced.py sample_domains.txt -a --html-report --html-report-file test_report.html --output-dir test_results

echo -e "\n\033[1;32mAll tests completed!\033[0m"
echo "Results saved in the test_results directory"
echo "====================================================="