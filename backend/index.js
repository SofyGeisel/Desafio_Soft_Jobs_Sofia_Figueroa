const jwt = require("jsonwebtoken")
const express = require('express')
const app = express()
const cors = require('cors')
const { verificarCredenciales, registrarUsuario, obtenerDatos, verificarCredencialesMiddleware, validarTokenMiddleware, reportarConsultasMiddleware } = require('./consultas')

app.listen(3000, console.log("SERVER ON"))
app.use(cors())
app.use(express.json())


app.post("/login", verificarCredencialesMiddleware, async (req, res) => {
    try {
    const { email, password } = req.body
    await verificarCredenciales(email, password)
    const token = jwt.sign({ email }, "az_AZ")
    res.send(token)
    } catch (error) {
    console.log(error)
    res.status(error.code || 500).send(error)
    }
    })

app.get("/usuarios", validarTokenMiddleware, async (req, res) => {
    try {
        const Authorization = req.header("Authorization")
        const token = Authorization.split("Bearer ")[1]
        jwt.verify(token, "az_AZ")
        const { email } = jwt.decode(token)
        const datos = await obtenerDatos(email)
        res.json(datos)

        
    } catch (error) {
        res.status(error.code || 500).send(error)        
    }
})

app.post("/usuarios", reportarConsultasMiddleware, async (req, res) => {
    try {
        const { email, password, rol, lenguage} = req.body
        await registrarUsuario(email, password, rol, lenguage)
        res.send("Usuario creado con éxito")
        
    } catch (error) {
        res.status(500).send(error)  
    }
})




