./create-network.sh

echo "Start malicious test..."

cd malicious-protocol/
./run.sh

echo "Complete malicious test!!"

echo "Start naive-mal test..."

cd ../naive-mal-protocol/
./run.sh
echo "Complete naive-mal test!!"

echo "Start naive-sh test..."
cd ../naive-sh-protocol/
./run.sh
echo "Complete naive-sh test!!"

echo "Start semi-honest test..."
cd ../semi-honest-protocol/
./run.sh
echo "Complete semi-honest test!!"