# svc-auth

Layanan backend autentikasi, manajemen pengguna, role-based access control (RBAC), dan manajemen perangkat untuk ekosistem Gumpalan. Bertanggung jawab atas pendaftaran pengguna, verifikasi kredensial (bcrypt), penautan multi-perangkat ke akun pengguna, penerbitan token sesi, dan penyediaan endpoint verifikasi untuk Nginx `auth_request`.

---

## Status

**Stabil & Aktif**: Menyediakan implementasi lengkap pendaftaran pengguna dan perangkat idempoten via hardware fingerprint, polling status, kontrol hak akses berbasis role & modul, terminal CLI admin independen, dan migrasi basis data multi-engine.

---

## Struktur Repositori

```text
svc-auth/
├── cmd/auth/main.go          # Titik masuk aplikasi HTTP server & CLI admin
├── internal/
│   ├── database/             # Abstraksi koneksi multi-mesin & auto-migrate goose
│   ├── device/               # Entitas domain & logika siklus hidup status perangkat
│   ├── httpapi/              # Implementasi HTTP handler & router (login, register, profil)
│   ├── store/                # Abstraksi persistensi data SQL (SQLite, MySQL, PostgreSQL)
│   ├── token/                # Verifikasi dan penerbitan token akses
│   └── user/                 # Entitas domain pengguna & peran (role)
├── migrations/
│   ├── 0001_init.sql         # Skema tabel auth_devices
│   ├── 0002_tokens.sql       # Skema tabel auth_tokens
│   ├── 0003_fingerprint.sql  # Indeks unik hardware fingerprint
│   ├── 0004_users_and_roles.sql # Skema tabel auth_roles, auth_users, & relasi user perangkat
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

## Manajemen CLI Terminal

Biner `auth` menyediakan antarmuka CLI terintegrasi untuk mengelola perangkat, akun pengguna, dan peran sistem (**role**) secara independen tanpa perlu antarmuka web khusus atau mematikan service.

### 1. Manajemen Perangkat (`auth device`)
```bash
# Menampilkan seluruh perangkat yang terdaftar beserta pemiliknya
go run ./cmd/auth device list

# Menyetujui perangkat (menerbitkan token akses baru)
go run ./cmd/auth device approve <DEVICE_ID>

# Mencabut otorisasi perangkat (menghapus seluruh token sesi aktif)
go run ./cmd/auth device revoke <DEVICE_ID>
```

### 2. Manajemen Pengguna (`auth user`)
```bash
# Menampilkan daftar pengguna terdaftar beserta peran dan modul akses
go run ./cmd/auth user list

# Membuat pengguna baru langsung dari terminal
go run ./cmd/auth user create <username> <password> [role] [display_name]
# Contoh:
go run ./cmd/auth user create anomali supersecret admin "Administrator Utama"

# Mereset kata sandi pengguna darurat
go run ./cmd/auth user reset-password <username> <new_password>
```

### 3. Manajemen Peran (`auth role`)
```bash
# Menampilkan seluruh peran dan modul yang diizinkan
go run ./cmd/auth role list

# Membuat peran baru dengan batasan modul tertentu
go run ./cmd/auth role create <name> <modules_comma_separated> [description]
# Contoh:
go run ./cmd/auth role create operator iot,camera "Operator Lapangan"
```

---

## Arsitektur RBAC Berjenjang

Gumpalan menerapkan pemisahan kontrol akses dua lapis (two-tiered RBAC):
1. **Lapis Gateway / Auth (`svc-auth`)**:
   - Menyimpan daftar modul tingkat tinggi yang boleh diakses role (`auth_roles.allowed_modules`), misal `["iot"]` atau `["*"]` untuk admin.
   - Pada saat verifikasi token via `/auth/v1/verify`, `svc-auth` menyuplai response header:
     - `X-Device-Id`: ID perangkat yang disetujui
     - `X-User-Id`: ID akun pengguna tertaut
     - `X-User-Role`: Nama peran pengguna (misal `admin`, `user`)
     - `X-Allowed-Modules`: Daftar modul yang diizinkan (misal `iot`)
   - Nginx mengevaluasi header ini untuk mengizinkan atau menolak (HTTP 403) permintaan ke modul terkait.
2. **Lapis Modul Layanan (misal `svc-iot`)**:
   - Menerima `X-User-Id` dan `X-User-Role` dari Nginx.
   - Menangani izin granular level komponen fisik (saklar, relay, kamera, tombol kontrol) menggunakan basis data internal masing-masing modul.

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

### Autentikasi & Registrasi
- `GET /healthz` - Health check status layanan lokal.
- `POST /auth/v1/register` - Menerima permohonan pendaftaran perangkat dan akun pengguna baru.
- `POST /auth/v1/login` - Autentikasi kredensial pengguna, pendaftaran perangkat otomatis jika baru, dan pengembalian token aktif jika perangkat telah disetujui.
- `GET /auth/v1/register/{deviceId}/status` - Memeriksa status persetujuan perangkat dan token akses.
- `GET /auth/v1/modules` - Mengambil daftar modul yang diizinkan untuk akun pengguna aktif.
- `GET /auth/v1/verify` - Endpoint verifikasi internal untuk otorisasi subrequest Nginx `auth_request` beserta injeksi header identitas pengguna dan role.

### Profil Pengguna & Manajemen Perangkat Klien (Bearer Token Required)
- `GET /auth/v1/user/profile` - Mengambil informasi akun pengguna dan peran saat ini.
- `PUT /auth/v1/user/profile` - Memperbarui display name pengguna.
- `PUT /auth/v1/user/password` - Mengganti kata sandi dengan verifikasi kata sandi lama.
- `GET /auth/v1/user/devices` - Menampilkan daftar seluruh perangkat tertaut pada akun pengguna.
- `DELETE /auth/v1/user/devices/{deviceId}` - Mencabut perangkat tertentu dari akun pengguna.

---

## Lisensi dan Dependensi

- `modernc.org/sqlite` (BSD-3-Clause) - Driver SQLite murni Go tanpa dependensi CGO.
- `github.com/go-sql-driver/mysql` (MPL-2.0) - Driver protokol MySQL/MariaDB.
- `github.com/jackc/pgx/v5` (MIT) - Driver PostgreSQL performa tinggi.
- `github.com/pressly/goose/v3` (MIT) - Pengelola migrasi skema basis data.
- `github.com/joho/godotenv` (MIT) - Pengurai berkas konfigurasi `.env`.
- `golang.org/x/crypto/bcrypt` (BSD-3-Clause) - Pengacakan dan hashing kata sandi aman.
