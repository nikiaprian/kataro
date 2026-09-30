# Mini redirect gate

Layanan kecil untuk mengarahkan domain, menolak negara tertentu, dan menolak bot yang jelas. Satu binary Go, tanpa database klik.

## Cara kerja

1. Buka `http://IP-SERVER:8080` atau `http://localhost:8080` untuk dashboard. Aplikasi ini tidak memakai domain sendiri. Dashboard minta login; nama dan kata sandi tertulis di `internal/server/auth.go`. Dari situ domain masuk, URL tujuan, dan negara yang diblokir bisa diubah, lalu tersimpan ke `config.yaml`.
2. Domain yang DNS-nya mengarah ke server ini, dan tercantum di `routes`, diarahkan (302). Query string permintaan ikut dibawa.
3. User-agent kosong atau yang cocok dengan pola bot ditolak (403, isi kosong).
4. Negara di daftar blokir ditolak dengan respons yang sama, hanya pada domain redirect.
5. Hostname lain mendapat 404.

Negara diambil dari header `CF-IPCountry` bila header itu ada (kecuali nilai `XX`, yang berarti tidak diketahui). Selain itu negara dibaca dari file GeoLite2 lokal. Tidak ada permintaan keluar per klik.

## Docker

Di server, dari folder proyek:

```sh
docker compose up -d
```

Perintah itu membangun image, menjalankan layanan, dan membuka port 8088 di server. Aplikasi di dalam container tetap memakai 8080. `-d` membuatnya tetap jalan setelah terminal ditutup. Dashboard ada di **http://IP-SERVER:8088/**. Volume `gate-data` menyimpan `config.yaml`, jadi domain dan negara yang diubah dari browser tetap ada setelah container dibuat ulang.

Saat domain masuk ditambahkan, aplikasi menulis konfigurasi nginx di server dan memuat ulangnya. Centang **Pasang SSL** bila sertifikat Let's Encrypt juga diminta. Nginx di server meneruskan domain itu ke `127.0.0.1:8088`.

Untuk memakai database negara, salin `GeoLite2-Country.mmdb` ke volume dan isi `geoip_db` dengan `/data/GeoLite2-Country.mmdb`.

## Menjalankan tanpa Docker

Butuh Go 1.22 atau lebih baru.

```powershell
copy config.example.yaml config.yaml
go run . -config config.yaml
```

Ubah `routes` di `config.yaml` ke domain dan URL tujuan Anda. Layanan hanya berbicara HTTP. Pasang HTTPS di Cloudflare atau reverse proxy di depannya.

## GeoLite2

Unduh **GeoLite2-Country** dalam format `.mmdb` dari akun MaxMind (gratis):

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Simpan berkasnya sebagai `GeoLite2-Country.mmdb` di sebelah binary, atau arahkan `geoip_db` ke path lain. Berkas ini tidak ikut dibagikan karena lisensinya.

Kalau origin hanya menerima traffic dari Cloudflare, `geoip_db` boleh dikosongkan. Negara lalu hanya berasal dari `CF-IPCountry`.

Port aplikasi jangan dibuka langsung ke internet bila Anda mengandalkan header Cloudflare. Klien yang bisa menyambung langsung bisa mengirim `CF-IPCountry` palsu. Batasi origin ke jaringan Cloudflare, atau taruh reverse proxy yang menimpa header itu.

## Reverse proxy

`X-Forwarded-For` hanya dipakai jika koneksi datang dari CIDR di `trusted_proxies`. Alamat yang dipilih adalah entri paling kanan yang bukan proxy tepercaya, supaya awalan palsu dari klien tidak mengganti IP asli.

`CF-Connecting-IP` hanya dipakai bila `CF-IPCountry` juga ada.

Contoh di belakang nginx di mesin yang sama:

```yaml
trusted_proxies:
  - 127.0.0.1/32
```

Proxy harus mengirim IP pengunjung di `X-Forwarded-For`.

## Blokir bot

Daftar bawaan menolak user-agent yang memuat potongan seperti `bot`, `spider`, `crawler`, `headless`, `curl`, `wget`, `python-requests`, dan klien otomatis sejenis. Pola tambahan bisa diisi di `bot.user_agent_contains`.

Bot yang meniru browser biasa tidak terdeteksi.

## Build untuk Linux

Dari Windows:

```powershell
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags "-s -w" -o gate .
```

Salin `gate`, `config.yaml`, dan `GeoLite2-Country.mmdb` ke server, lalu jalankan:

```sh
./gate -config config.yaml
```
