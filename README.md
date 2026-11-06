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

### Acceso del administrador
- Usuario: `admin`
- La contraseña se configura de forma privada y puede cambiarse desde `/admin.html`.
- No publiques contraseñas ni hashes en la documentación.

## Despliegue (Railway / Render / VPS)
1. Sube esta carpeta a GitHub.
2. Crea un servicio Node: comando `npm start`.
3. Puerto: la variable `PORT` la asigna la plataforma.
4. Persiste la carpeta `data/` (volumen) para no perder licencias al reiniciar.

## API clave
- `GET /api/access/check?classCode=XXXX` → `{ allowed: true/false }`
- Los juegos deben consultar esto **antes** de habilitar el reto.

## Seguridad
- Contraseñas con hash scrypt y migración automática de hashes antiguos.
- Límite de intentos de inicio de sesión y tokens de sesión temporales.
- No uses una base de datos de producción dentro de un repositorio público.
- Tokens de sesión con expiración 12 h.
- Sin licencia activa no hay configuración ni resultados.
