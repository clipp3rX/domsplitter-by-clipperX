#!/bin/bash

# Domain Splitter Advanced Installation Script
echo "====================================================="
echo "  Domain Splitter Advanced - Installation Script"
echo "====================================================="

# Check if Python 3 is installed
if command -v python3 &>/dev/null; then
    echo "[✓] Python 3 is installed"
    PYTHON_CMD="python3"
elif command -v python &>/dev/null && python --version 2>&1 | grep -q "Python 3"; then
    echo "[✓] Python 3 is installed"
    PYTHON_CMD="python"
else
    echo "[✗] Python 3 is not installed. Please install Python 3.6 or higher."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print('{}.{}'.format(sys.version_info.major, sys.version_info.minor))")
PYTHON_VERSION_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_VERSION_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_VERSION_MAJOR" -lt 3 ] || ([ "$PYTHON_VERSION_MAJOR" -eq 3 ] && [ "$PYTHON_VERSION_MINOR" -lt 6 ]); then
    echo "[✗] Python version $PYTHON_VERSION is not supported. Please install Python 3.6 or higher."
    exit 1
else
    echo "[✓] Python version $PYTHON_VERSION is supported"
fi

# Check if pip is installed
if command -v pip3 &>/dev/null; then
    PIP_CMD="pip3"
elif command -v pip &>/dev/null; then
    PIP_CMD="pip"
else
    echo "[✗] pip is not installed. Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    $PYTHON_CMD get-pip.py
    rm get-pip.py
    
    if command -v pip3 &>/dev/null; then
        PIP_CMD="pip3"
    elif command -v pip &>/dev/null; then
        PIP_CMD="pip"
    else
        echo "[✗] Failed to install pip. Please install pip manually."
        exit 1
    fi
fi

echo "[✓] pip is installed"

# Create virtual environment
echo "Creating virtual environment..."
$PYTHON_CMD -m venv venv
if [ $? -ne 0 ]; then
    echo "[✗] Failed to create virtual environment. Installing venv..."
    $PIP_CMD install virtualenv
    $PYTHON_CMD -m virtualenv venv
    if [ $? -ne 0 ]; then
        echo "[✗] Failed to create virtual environment. Continuing without it..."
        VENV_PYTHON=$PYTHON_CMD
        VENV_PIP=$PIP_CMD
    else
        echo "[✓] Virtual environment created"
        if [ -f venv/bin/activate ]; then
            source venv/bin/activate
        else
            source venv/Scripts/activate
        fi
        VENV_PYTHON="python"
        VENV_PIP="pip"
    fi
else
    echo "[✓] Virtual environment created"
    if [ -f venv/bin/activate ]; then
        source venv/bin/activate
    else
        source venv/Scripts/activate
    fi
    VENV_PYTHON="python"
    VENV_PIP="pip"
fi

# Install dependencies
echo "Installing dependencies..."
$VENV_PIP install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[✗] Failed to install dependencies. Please check the error message above."
    exit 1
else
    echo "[✓] Dependencies installed successfully"
fi

# Make the script executable
chmod +x domain_splitter_advanced.py

echo "====================================================="
echo "[✓] Installation completed successfully!"
echo "====================================================="
echo ""
echo "To use Domain Splitter Advanced:"
echo ""
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate  # On Linux/Mac"
echo "   venv\\Scripts\\activate     # On Windows"
echo ""
echo "2. Run the tool:"
echo "   ./domain_splitter_advanced.py sample_domains.txt --all"
echo ""
echo "3. For help and options:"
echo "   ./domain_splitter_advanced.py --help"
echo ""
echo "====================================================="