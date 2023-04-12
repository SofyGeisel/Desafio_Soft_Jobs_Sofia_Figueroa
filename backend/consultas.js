const { Pool } = require('pg')
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken")

const pool = new Pool({
    host: 'localhost',
    user: 'postgres',
    password: 'sofy',
    database: 'softjobs',
    allowExitOnIdle: true
})

const verificarCredenciales = async (email, password) => {
    const values = [email]
    const consulta = "SELECT * FROM usuarios WHERE email = $1"

    const { rows: [usuario], rowCount } = await pool.query(consulta, values)

    const { password: passwordEncriptada } = usuario
    const passwordEsCorrecta = bcrypt.compareSync(password, passwordEncriptada)

    if (!passwordEsCorrecta || !rowCount)
        throw { code: 401, message: "Email o contraseña incorrecta" }
}

const registrarUsuario = async (email, password, rol, lenguage) => {
    const passwordEncriptada =bcrypt.hashSync(password)
    password = passwordEncriptada
    const values = [email, passwordEncriptada, rol, lenguage]
    const consulta = "INSERT INTO usuarios values (DEFAULT, $1, $2, $3, $4)"
    await pool.query(consulta, values)
}

const obtenerDatos = async (email) => {
    const consulta = "SELECT * FROM usuarios WHERE  email = $1"
    const values = [email]
    const { rows: [usuario], rowCount } = await pool.query(consulta, values)
    if (!rowCount) {
        throw { code: 404, message: "Usuario no encontrado"}
    }
    delete usuario.password
    return usuario 
}

const verificarCredencialesMiddleware = async (req, res, next) => {
    try {
        const { email, password } = req.body
        await verificarCredenciales(email, password)
        next()
    } catch (error) {
        res.status(error.code || 500).send(error)
    }
}


const validarTokenMiddleware = (req, res, next) => {
    try {
        const Authorization = req.header("Authorization")
        const token = Authorization.split("Bearer ")[1]
        jwt.verify(token, "az_AZ")
        next()
    } catch (error) {
        res.status(401).send("Token inválido")
    }
}

const reportarConsultasMiddleware = (req, res, next) => {
    console.log(`Solicitud recibida: ${req.method} ${req.path}`)
    next()
}


module.exports = { verificarCredenciales, registrarUsuario, obtenerDatos, verificarCredencialesMiddleware, validarTokenMiddleware, reportarConsultasMiddleware }