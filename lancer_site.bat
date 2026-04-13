@echo off
echo Lancement de CryptoCloud...
cd /d "%~dp0"
python -m pip install -r requirements.txt --quiet
python main.py
pause
