#!/data/data/com.termux/files/usr/bin/bash
set -e

pkg update -y
pkg install -y python git procps net-tools iproute2 iptables

mkdir -p "$HOME/.phoneguard"
cp "$(dirname "$0")/phoneguard.py" "$HOME/.phoneguard/phoneguard.py"
chmod +x "$HOME/.phoneguard/phoneguard.py"

mkdir -p "$HOME/.termux/boot"
cat > "$HOME/.termux/boot/phoneguard" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
python "$HOME/.phoneguard/phoneguard.py" --once
EOF
chmod +x "$HOME/.termux/boot/phoneguard"

python "$HOME/.phoneguard/phoneguard.py" --apply

echo "Kurulum tamamlandı."
echo "Çalıştırmak için: python ~/.phoneguard/phoneguard.py --once"
echo "İzleme modu için: python ~/.phoneguard/phoneguard.py --watch"
