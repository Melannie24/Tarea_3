# Tarea_3
Aplicación de cifrado

# 🔐 Sistema de Cifrado Asimétrico con Tokens de Uso Único

Aplicación web desarrollada en Flask que permite cifrar mensajes de forma segura utilizando criptografía RSA, generar tokens de acceso únicos y mantener un historial de auditoría.

---

## 📖 Descripción

Este sistema permite a los usuarios:

- Cifrar mensajes utilizando criptografía asimétrica (RSA 2048 bits)
- Generar un token único para acceder al mensaje
- Descifrar mensajes mediante token (uso único)
- Mantener un registro de auditoría de todas las acciones

El sistema está diseñado con un enfoque en seguridad, control de acceso y trazabilidad.

---

## 🏗️ Arquitectura

- Backend: Flask (Python)
- Base de datos: SQLite
- Seguridad:
  - RSA (cifrado/descifrado)
  - Hash de contraseñas
  - Tokens únicos
- Arquitectura: Monolítica (MVC simplificado)

---

## 🚀 Funcionalidades

- 🔐 **Cifrado RSA (2048 bits):** Seguridad de nivel industrial  
- 🎟️ **Tokens de un solo uso:** El mensaje solo puede ser leído una vez  
- ⏳ **Expiración de tokens:** Los tokens tienen tiempo de validez  
- 🗑️ **Borrado lógico:** Permite inactivar registros  
- 📊 **Auditoría completa:** Registro de IP, fecha, hora y dispositivo  
- 🔒 **Autenticación:** Login y registro de usuarios  

---

## 📂 Estructura del Proyecto
