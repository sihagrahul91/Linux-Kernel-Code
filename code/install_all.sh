cd procmodules
sh install_modules.sh
cd ..
sh install.sh
echo "5" > /proc/kernel-queue
echo "5" > /proc/trashbin-max
