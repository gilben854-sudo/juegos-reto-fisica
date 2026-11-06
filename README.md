# Juegos de Reto para Física — Control SaaS

Producido por GILAST


Sistema de **control de acceso por licencia** para los juegos educativos.

## Control
- **Admin**: crea profesores, activa (+30 días / +1 año) o **suspende**.
- **Profesor**: registro con prueba 7 días, configura correo de certificados, ve código de clase y resultados.
- **Alumno**: entra con código de clase; si la licencia del profe no está activa → **bloqueado**.

## Arranque local
```bash
cd saas-platform
npm install
npm start
```
Abre http://localhost:3780

### Admin por defecto
- Usuario: `admin`
- Contraseña: `NewtonSaaS2026!`
**Cámbiala en producción.**

## Despliegue (Railway / Render / VPS)
1. Sube esta carpeta a GitHub.
2. Crea un servicio Node: comando `npm start`.
3. Puerto: la variable `PORT` la asigna la plataforma.
4. Persiste la carpeta `data/` (volumen) para no perder licencias al reiniciar.

## API clave
- `GET /api/access/check?classCode=XXXX` → `{ allowed: true/false }`
- Los juegos deben consultar esto **antes** de habilitar el reto.

## Seguridad
- Contraseñas con hash SHA-256 + salt (mejorable a bcrypt en producción).
- Tokens de sesión con expiración 12 h.
- Sin licencia activa no hay configuración ni resultados.
