for i in $(seq 1 5); do
  html=$(curl -s "https://coupon-one-time-3.onrender.com/coupon?offer=mcd-bogo")
  # extract token from img src like /api/qrcode/TOKEN
  token=$(echo "$html" | sed -n 's/.*\/api\/qrcode\/\([^"]*\)".*/\1/p' | head -n1)
  echo "TOKEN $i: $token"
done
