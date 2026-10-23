# svc-auth

Layanan backend autentikasi untuk platform Gumpalan. Bertanggung jawab atas pendaftaran perangkat, verifikasi kunci publik, penerbitan token, dan endpoint verifikasi untuk Nginx `auth_request`.

> **Catatan modul**: Path modul `github.com/gumpalan/svc-auth` pada `go.mod` adalah placeholder.

## Status

**Scaffold** (kerangka awal dengan migrasi SQLite/MySQL/PostgreSQL, pemuatan konfigurasi, dan healthz endpoint).

## Struktur Repositori

```
svc-auth/
├── cmd/auth/main.go          # Titik masuk aplikasi
├── internal/
│   ├── database/             # Koneksi multi-mesin, dialect rebind, auto-migrate
│   ├── device/               # Manajemen status persetujuan perangkat
│   ├── httpapi/              # Implementasi router OpenAPI
│   ├── store/                # Abstraksi akses database
│   └── token/                # Verifikasi dan penerbitan token JWT
├── migrations/
│   ├── 0001_init.sql         # Skema goose portabel tabel auth_devices
│   └── fs.go                 # embed.FS berkas migrasi
├── .env.example              # Contoh variabel lingkungan
├── Makefile                  # Perintah build, test, dan cross-compile arm64
└── README.md
```

## Cara Menjalankan

```bash
# Salin konfigurasi environment
cp .env.example .env

# Jalankan lokal
make run

# Tes unit
make test

# Build biner lokal
make build

# Cross-compile untuk Linux ARM64 (STB / Single Board Computer)
make build-arm64
```

## Konfigurasi Database

Database ditentukan via environment variable (kompatibel Laravel):

| Variabel | Pilihan Nilai | Default | Keterangan |
| --- | --- | --- | --- |
| `DB_CONNECTION` | `sqlite`, `mysql`, `mariadb`, `pgsql` | `sqlite` | Mesin database |
| `DB_DATABASE` | String | `./data/auth.db` | Path berkas sqlite atau nama database |
| `DB_HOST` | Host / IP | `127.0.0.1` | Host database server |
| `DB_PORT` | Angka | `3306` / `5432` | Port server database |
| `DB_USERNAME` | String | - | Username database |
| `DB_PASSWORD` | String | - | Password database |
| `DB_SSLMODE` | `disable`, `require`, dll | `disable` | Khusus PostgreSQL |
| `DB_URL` | DSN lengkap | - | Menimpa variabel di atas jika diisi |
| `DB_AUTO_MIGRATE` | `true`, `false` | `true` | Menjalankan migrasi saat startup |

## Daftar Endpoint

Spesifikasi resmi dikelola terpusat di `api-specs/auth/v1/openapi.yaml`.

- `GET /healthz` - Status kesehatan service lokal
- `POST /auth/v1/register` - Mengirim permintaan pendaftaran perangkat baru
- `GET /auth/v1/register/{deviceId}/status` - Mengecek status persetujuan perangkat
- `GET /auth/v1/modules` - Mendapatkan daftar modul yang diizinkan untuk perangkat
- `GET /auth/v1/verify` - Endpoint verifikasi internal untuk Nginx `auth_request`

## Rencana Pengujian Database Tambahan

Tes unit saat ini mencakup SQLite in-memory, parser konfigurasi, dan rebind placeholder PostgreSQL. Pengujian integrasi MariaDB dan PostgreSQL nyata direncanakan menggunakan runner kontainer terisolasi pada fase berikutnya.

## Lisensi dan Dependensi

Lisensi repositori ini **belum ditentukan**.

### Dependensi Langsung:
- `modernc.org/sqlite` (BSD-3-Clause) - Driver SQLite pure Go tanpa CGO.
- `github.com/go-sql-driver/mysql` (MPL-2.0) - Driver MySQL/MariaDB. Berlisensi copyleft tingkat berkas; aman digunakan sebagai pustaka tanpa modifikasi berkas driver.
- `github.com/jackc/pgx/v5` (MIT) - Driver PostgreSQL stdlib.
- `github.com/pressly/goose/v3` (MIT) - Pustaka migrasi database.
- `github.com/joho/godotenv` (MIT) - Parser berkas .env.

### Memeriksa Lisensi:
Gunakan pustaka audit lisensi Go:
```bash
go run github.com/google/go-licenses@latest report ./...
```
