# Thư mục ảnh minh họa

## Ảnh AES (mục 1.1.1)

| Tên file | Nội dung |
|---|---|
| `aes-01-tong-quan.png`   | Mô hình tổng quát AES (luồng các vòng + Key Expansion) |
| `aes-02-subbytes.png`    | Bước SubBytes (tra S-box) |
| `aes-03-shiftrows.png`   | Bước ShiftRows (dịch hàng) |
| `aes-04-mixcolumns.png`  | Bước MixColumns (nhân ma trận trên GF(2^8)) |
| `aes-05-addroundkey.png` | Bước AddRoundKey (XOR khóa vòng) |
| `aes-06-gcm.png`         | (tùy chọn) Chế độ AES-GCM (CTR + GHASH) |

## Ảnh trao đổi khóa (mục 1.1.2)

| Tên file                  | Nội dung |
|---------------------------|---|
| `dh-01-trao-doi-khoa.png` | Trao đổi khóa Diffie–Hellman hữu hạn (g^a, g^b → g^ab) |

## Ảnh chữ ký số (mục 1.1.3)

| Tên file                    | Nội dung |
|-----------------------------|---|
| `rsa-pss-01-ky.png`         | Ký RSA-PSS (mHash/salt → H → maskedDB → EM → σ = EM^d) |
| `rsa-pss-02-xac-minh.png`   | Xác minh RSA-PSS (σ → EM = σ^e → lấy lại salt → so H' == H) |

