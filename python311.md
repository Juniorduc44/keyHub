# Python 3.11 Installation Guide

This guide will help you install Python 3.11 on Ubuntu/Debian-based Linux systems while keeping your default Python installation intact.

## Prerequisites

- Ubuntu or Debian-based Linux system
- Terminal access
- sudo privileges

## Installation Steps

### 1. Add Universe Repository(as oppose to deadsnakes version)
```bash
sudo add-apt-repository universe
```

### 2. Update Package List
```bash
sudo apt update
```

### 3. Install Python 3.11
```bash
sudo apt install python3.11
```

### 4. Install pip for Python 3.11
```bash
curl -sS https://bootstrap.pypa.io/get-pip.py | sudo python3.11
```

### 5. Install Virtual Environment Support
```bash
sudo apt install python3.11-venv
```

## Verification

Verify your installation by checking the Python version:
```bash
python3.11 --version
```

Check pip installation:
```bash
python3.11 -m pip --version
```

## Using Virtual Environments

### Create a New Virtual Environment
```bash
python3.11 -m venv myenv_py311
```

### Activate the Virtual Environment
```bash
source myenv_py311/bin/activate
```

When activated, you'll see `(myenv_py311)` in your terminal prompt.

### Deactivate the Virtual Environment
When you're done working in the virtual environment:
```bash
deactivate
```

## Installing Packages

With virtual environment activated:
```bash
pip install package_name
```

Or without virtual environment (not recommended):
```bash
python3.11 -m pip install package_name
```

## Important Notes

- Your system's default Python installation remains unchanged
- Always use virtual environments for projects to avoid conflicts
- When working with Python 3.11 specifically, use `python3.11` command
- Use `pip install` only after activating a virtual environment

## Troubleshooting

If you encounter permission errors:
1. Make sure you have sudo privileges
2. Try running the commands with `sudo` if necessary
3. For pip installations, prefer using virtual environments over system-wide installations

## Next Steps

1. Create a virtual environment for your project
2. Install required packages within the virtual environment
3. Start developing with Python 3.11!

## Additional Resources

- [Python Documentation](https://docs.python.org/3.11/)
- [pip Documentation](https://pip.pypa.io/en/stable/)
- [venv Documentation](https://docs.python.org/3/library/venv.html)


</br>
</br>

## Return to [Start](./README.md)