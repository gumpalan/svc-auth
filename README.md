# svc-auth

Layanan backend autentikasi dan manajemen perangkat untuk ekosistem Gumpalan. Bertanggung jawab atas pendaftaran perangkat, verifikasi identitas, penerbitan token sesi, dan penyediaan endpoint verifikasi untuk Nginx `auth_request`.

---

## Status

**Stabil & Aktif**: Menyediakan implementasi lengkap pendaftaran perangkat idempoten via hardware fingerprint, polling status, terminal CLI admin independen, dan migrasi basis data multi-engine.

---

## Struktur Repositori

```text
svc-auth/
├── cmd/auth/main.go          # Titik masuk aplikasi HTTP server & CLI admin
├── internal/
│   ├── database/             # Abstraksi koneksi multi-mesin & auto-migrate goose
│   ├── device/               # Entitas domain & logika siklus hidup status perangkat
│   ├── httpapi/              # Implementasi HTTP handler & router
│   ├── store/                # Abstraksi persistensi data SQL (SQLite, MySQL, PostgreSQL)
│   └── token/                # Verifikasi dan penerbitan token akses
├── migrations/
│   ├── 0001_init.sql         # Skema tabel auth_devices
│   ├── 0002_tokens.sql       # Skema tabel auth_tokens
│   ├── 0003_fingerprint.sql  # Indeks unik hardware fingerprint (anti-duplikasi pendaftaran)
│   └── fs.go                 # embed.FS berkas migrasi SQL
├── .env.example              # Template konfigurasi variabel lingkungan
├── Makefile                  # Otomasi build, test, dan cross-compile Linux ARM64
└── README.md
```

---

## Panduan Penggunaan

### 1. Konfigurasi Lingkungan
```bash
cp .env.example .env
```

### 2. Menjalankan Layanan Lokal
```bash
# Menggunakan Makefile
make run

# Atau langsung via Go CLI
go run ./cmd/auth
```

Layanan HTTP berjalan secara default pada port `8001`.

### 3. Eksekusi Pengujian Unit
```bash
make test
# atau: go test ./...
```

### 4. Kompilasi Biner
```bash
# Kompilasi native biner lokal (output: bin/auth)
make build

# Cross-compile untuk Linux ARM64 (STB / Single Board Computer)
make build-arm64
```

---

## Manajemen Perangkat via Terminal CLI

Biner `auth` menyediakan antarmuka CLI terintegrasi untuk mengelola siklus hidup perangkat secara independen **tanpa perlu menghentikan layanan HTTP yang sedang berjalan**. CLI terhubung langsung ke mesin database yang dikonfigurasi.

### Perintah CLI

```bash
# Menampilkan seluruh perangkat yang terdaftar
go run ./cmd/auth device list

# Menyetujui perangkat (menerbitkan token akses baru)
go run ./cmd/auth device approve <DEVICE_ID>

# Mencabut otorisasi perangkat (menghapus token akses aktif)
go run ./cmd/auth device revoke <DEVICE_ID>
```

Jika telah dikompilasi via `make build`:
```bash
./bin/auth device list
./bin/auth device approve <DEVICE_ID>
./bin/auth device revoke <DEVICE_ID>
```

Contoh keluaran `device list`:
```text
DEVICE ID                              NAMA               STATUS    TERDAFTAR             DISETUJUI
a1b2c3d4-e5f6-7890-abcd-ef1234567890   Pixel 8 Pro        pending   2026-10-25 10:30:00   -
f0e1d2c3-b4a5-6789-0fed-cba987654321   Samsung S24 Ultra  approved  2026-10-24 08:15:00   2026-10-24 09:00:00
```

---

## Konfigurasi Basis Data

Mendukung berbagai mesin basis data melalui variabel lingkungan:

| Variabel | Pilihan Nilai | Default | Keterangan |
| --- | --- | --- | --- |
| `DB_CONNECTION` | `sqlite`, `mysql`, `mariadb`, `pgsql` | `sqlite` | Driver mesin basis data |
| `DB_DATABASE` | String | `./data/auth.db` | Jalur berkas SQLite atau nama basis data |
| `DB_HOST` | Host / IP | `127.0.0.1` | Alamat host server basis data |
| `DB_PORT` | Angka | `3306` / `5432` | Port server basis data |
| `DB_USERNAME` | String | - | Nama pengguna basis data |
| `DB_PASSWORD` | String | - | Kata sandi basis data |
| `DB_SSLMODE` | `disable`, `require`, dll | `disable` | Mode SSL khusus PostgreSQL |
| `DB_URL` | DSN lengkap | - | Menimpa parameter konfigurasi individual di atas |
| `DB_AUTO_MIGRATE` | `true`, `false` | `true` | Menjalankan migrasi skema saat startup |

---

## Daftar Endpoint API

Spesifikasi kontrak antarmuka dikelola secara terpusat pada `api-specs/auth/v1/openapi.yaml`.

- `GET /healthz` - Health check status layanan lokal.
- `POST /auth/v1/register` - Menerima permohonan pendaftaran perangkat baru (idempoten via fingerprint).
- `GET /auth/v1/register/{deviceId}/status` - Memeriksa status persetujuan perangkat dan token akses.
- `GET /auth/v1/modules` - Mengambil daftar modul yang diizinkan untuk perangkat.
- `GET /auth/v1/verify` - Endpoint verifikasi internal untuk otorisasi subrequest Nginx `auth_request`.

---

## Lisensi dan Dependensi

- `modernc.org/sqlite` (BSD-3-Clause) - Driver SQLite murni Go tanpa dependensi CGO.
- `github.com/go-sql-driver/mysql` (MPL-2.0) - Driver protokol MySQL/MariaDB.
- `github.com/jackc/pgx/v5` (MIT) - Driver PostgreSQL performa tinggi.
- `github.com/pressly/goose/v3` (MIT) - Pengelola migrasi skema basis data.
- `github.com/joho/godotenv` (MIT) - Pengurai berkas konfigurasi `.env`.
