require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const { cpf } = require('cpf-cnpj-validator');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '../frontend')));

const SECRET_KEY = process.env.JWT_SECRET || 'belutti_chave_secreta_super_segura';
const PORT = process.env.PORT || 3000;

// Conexão com PostgreSQL (Neon)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Helper para formatar data/hora no fuso de Brasília/Recife
function formatOrderDate(rawTimestamp) {
    const dateObj = rawTimestamp instanceof Date ? rawTimestamp : new Date(rawTimestamp);
    return dateObj.toLocaleString('pt-BR', {
        timeZone: 'America/Sao_Paulo',
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Inicialização das tabelas e seed inicial de produtos
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                cpf VARCHAR(11) UNIQUE NOT NULL,
                birth_date VARCHAR(10) NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                address JSONB NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                reset_token TEXT,
                reset_expires BIGINT
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                items JSONB NOT NULL,
                total NUMERIC(10, 2) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pedido Confirmado',
                shipping_address JSONB,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                category VARCHAR(50) NOT NULL,
                price NUMERIC(10, 2) NOT NULL,
                color VARCHAR(30),
                fit VARCHAR(30),
                image TEXT NOT NULL,
                stock INTEGER DEFAULT 15,
                featured BOOLEAN DEFAULT FALSE
            )
        `);

        // Popula produtos iniciais caso a tabela esteja vazia
        const { rows } = await pool.query('SELECT COUNT(*) FROM products');
        if (parseInt(rows[0].count) === 0) {
            await pool.query(`
                INSERT INTO products (name, category, price, color, fit, image, stock, featured) VALUES
                ('Casaco Moletom', 'moletons', 89.90, 'preto', 'regular', '/img/modelo-1.jpeg', 12, TRUE),
                ('Camisa OVERSIZED', 'camisas', 84.90, 'branco', 'oversized', '/img/modelo-2.jpeg', 15, TRUE),
                ('Calça Baggy', 'calcas', 149.90, 'preto', 'regular', '/img/modelo-3.jpeg', 10, TRUE),
                ('Regata Canelada', 'camisas', 59.90, 'branco', 'slim', '/img/modelo-4.jpg', 20, TRUE),
                ('Camisa em Linho Azul-Marinho', 'camisas', 79.90, 'azul', 'regular', '/img/camisa-azul-linho.jpg', 10, FALSE),
                ('Camisa em Linho Marrom', 'camisas', 79.90, 'marrom', 'regular', '/img/camisa_marrom-linho.jpg', 10, FALSE),
                ('Camisa em Linho Off-White', 'camisas', 79.90, 'branco', 'regular', '/img/camisa-off-white-linho.jpg', 10, FALSE),
                ('Camisa Malha Cotton Marrom', 'camisas', 69.90, 'marrom', 'slim', '/img/camisa-marrom-malha-cotton.jpeg', 14, FALSE),
                ('Camisa Malha Cotton Preto', 'camisas', 69.90, 'preto', 'regular', '/img/camisa-preta-malha-cotton.jpeg', 18, FALSE),
                ('Camisa Malha Cotton Vermelho', 'camisas', 69.90, 'vermelho', 'regular', '/img/camisa-vermelha-malha-cotton.jpeg', 8, FALSE),
                ('Camisa Malha Cotton Verde', 'camisas', 69.90, 'verde', 'regular', '/img/camisa-verde-malha-cotton.jpeg', 9, FALSE),
                ('Camisa de Tricot Azul', 'camisas', 69.90, 'azul', 'regular', '/img/camisa-azul-tricot.jpeg', 7, FALSE),
                ('Camisa Manga Longa Preta', 'camisas', 129.90, 'preto', 'manga-longa', '/img/camisa-preta-tricot.jpeg', 11, FALSE),
                ('Camisa Branca Minimalista', 'camisas', 99.90, 'branco', 'slim', '/img/camisa-vermelha-tricot.jpeg', 13, FALSE),
                ('Camisa Manga Longa Azul', 'camisas', 139.90, 'azul', 'manga-longa', '/img/camisa-azul-manga-longa.jpeg', 6, FALSE),
                ('Camiseta Básica Rosa Salmão', 'camisas', 79.90, 'rosa', 'regular', '/img/camisa-marrom-manga-longa.jpeg', 12, FALSE),
                ('Camisa Manga Longa Preto', 'camisas', 159.90, 'preto', 'manga-longa', '/img/camisa-preta-manga-longa.jpeg', 9, FALSE)
            `);
            console.log('Catálogo inicial da Belutti populado no PostgreSQL.');
        }

        console.log('Conectado ao PostgreSQL (Neon) e tabelas verificadas.');
    } catch (err) {
        console.error('Erro ao inicializar o banco PostgreSQL:', err.message);
    }
}

initDatabase();

// Middlewares de autenticação e permissão de administrador
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Você precisa estar logado.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sessão expirada. Faça login novamente.' });
        req.user = user;
        next();
    });
}

async function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, async () => {
        try {
            const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
            if (!rows[0] || !rows[0].is_admin) {
                return res.status(403).json({ error: 'Acesso restrito a administradores.' });
            }
            next();
        } catch (err) {
            res.status(500).json({ error: 'Erro ao verificar permissões.' });
        }
    });
}

function isAtLeast18(birthDateStr) {
    if (!birthDateStr) return false;
    const today = new Date();
    const [year, month, day] = birthDateStr.split('-').map(Number);

    let age = today.getFullYear() - year;
    const monthDiff = today.getMonth() - (month - 1);
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < day)) {
        age--;
    }
    return age >= 18;
}

// ==========================================
// ROTAS DE PRODUTOS E ESTOQUE
// ==========================================
app.get('/products', async (req, res) => {
    const { category, featured } = req.query;
    try {
        let query = 'SELECT * FROM products WHERE 1=1';
        const params = [];

        if (category) {
            params.push(category);
            query += ` AND category = $${params.length}`;
        }
        if (featured === 'true') {
            query += ' AND featured = TRUE';
        }
        query += ' ORDER BY id ASC';

        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao carregar produtos.' });
    }
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO E CONTA
// ==========================================
app.post('/register', async (req, res) => {
    const { name, cpf: userCpf, birthDate, email, password, address } = req.body;
    
    if (!cpf.isValid(userCpf)) {
        return res.status(400).json({ field: 'cpf', error: 'CPF inválido. Verifique os números digitados.' });
    }
    if (!isAtLeast18(birthDate)) {
        return res.status(400).json({ field: 'birthDate', error: 'Cadastro permitido apenas para maiores de 18 anos.' });
    }
    if (!address || !address.cep || !address.number) {
        return res.status(400).json({ field: 'cep', error: 'Endereço completo é obrigatório.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (name, cpf, birth_date, email, password, address) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, is_admin`,
            [name, userCpf, birthDate, email, hashedPassword, JSON.stringify(address)]
        );

        const newUser = result.rows[0];
        const token = jwt.sign(
            { id: newUser.id, email, name, isAdmin: newUser.is_admin },
            SECRET_KEY,
            { expiresIn: '2h' }
        );

        res.status(201).json({
            message: 'Conta criada com sucesso!',
            token,
            userName: name.split(' ')[0],
            isAdmin: newUser.is_admin
        });
    } catch (err) {
        if (err.code === '23505') {
            if (err.constraint && err.constraint.includes('cpf')) {
                return res.status(400).json({ field: 'cpf', error: 'Este CPF já está cadastrado.' });
            }
            return res.status(400).json({ field: 'email', error: 'Este e-mail já está cadastrado.' });
        }
        res.status(500).json({ error: 'Erro interno no servidor.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = rows[0];

        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Senha incorreta.' });

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name, isAdmin: user.is_admin },
            SECRET_KEY,
            { expiresIn: '2h' }
        );

        res.json({
            message: 'Login aprovado!',
            token,
            userName: user.name.split(' ')[0],
            isAdmin: user.is_admin
        });
    } catch (err) {
        res.status(500).json({ error: 'Erro no banco de dados.' });
    }
});

// Solicitar token de redefinição de senha
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (!rows[0]) {
            return res.status(404).json({ error: 'Nenhuma conta encontrada com este e-mail.' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // 1 hora

        await pool.query(
            'UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3',
            [resetToken, expires, rows[0].id]
        );

        res.json({
            message: 'Código de recuperação gerado com sucesso!',
            resetToken
        });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao processar solicitação.' });
    }
});

// Redefinir senha com token
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'A nova senha deve ter pelo menos 6 caracteres.' });
    }

    try {
        const { rows } = await pool.query(
            'SELECT id FROM users WHERE reset_token = $1 AND reset_expires > $2',
            [token, Date.now()]
        );

        if (!rows[0]) {
            return res.status(400).json({ error: 'Token inválido ou expirado.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2',
            [hashedPassword, rows[0].id]
        );

        res.json({ message: 'Senha redefinida com sucesso! Faça login.' });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao redefinir senha.' });
    }
});

app.get('/me', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, name, cpf, birth_date, email, address, is_admin FROM users WHERE id = $1',
            [req.user.id]
        );
        if (!rows[0]) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao buscar dados do usuário.' });
    }
});

app.put('/me', authenticateToken, async (req, res) => {
    const { name, email, newPassword, address } = req.body;
    const userId = req.user.id;
    const addressJson = JSON.stringify(address || {});

    try {
        if (newPassword && newPassword.trim().length >= 6) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await pool.query(
                'UPDATE users SET name = $1, email = $2, password = $3, address = $4 WHERE id = $5',
                [name, email, hashedPassword, addressJson, userId]
            );
            res.json({ message: 'Dados, senha e endereço atualizados!', userName: name.split(' ')[0] });
        } else {
            await pool.query(
                'UPDATE users SET name = $1, email = $2, address = $3 WHERE id = $4',
                [name, email, addressJson, userId]
            );
            res.json({ message: 'Dados e endereço atualizados com sucesso!', userName: name.split(' ')[0] });
        }
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ field: 'email', error: 'Este e-mail já está em uso por outra conta.' });
        }
        res.status(500).json({ error: 'Erro ao atualizar cadastro.' });
    }
});

// Excluir a própria conta do usuário logado
app.delete('/me', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM orders WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM users WHERE id = $1', [userId]);
        await client.query('COMMIT');
        res.json({ message: 'Sua conta foi excluída permanentemente.' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Erro ao excluir conta.' });
    } finally {
        client.release();
    }
});

// ==========================================
// ROTAS DE PEDIDOS (COM ESTOQUE E ENDEREÇO)
// ==========================================
app.post('/orders', authenticateToken, async (req, res) => {
    const { items, total } = req.body;
    const userId = req.user.id;

    if (!items || items.length === 0) {
        return res.status(400).json({ error: 'O carrinho está vazio.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Busca o endereço atual do cliente para registrar no pedido
        const userRes = await client.query('SELECT address FROM users WHERE id = $1', [userId]);
        const shippingAddress = userRes.rows[0]?.address || {};

        // 2. Valida e abate o estoque de cada item comprado
        for (const item of items) {
            const prodRes = await client.query('SELECT id, stock FROM products WHERE name = $1 FOR UPDATE', [item.name]);
            if (prodRes.rows[0]) {
                if (prodRes.rows[0].stock < item.quantity) {
                    await client.query('ROLLBACK');
                    return res.status(400).json({
                        error: `Estoque insuficiente para "${item.name}". Restam apenas ${prodRes.rows[0].stock} unidade(s).`
                    });
                }
                await client.query(
                    'UPDATE products SET stock = stock - $1 WHERE id = $2',
                    [item.quantity, prodRes.rows[0].id]
                );
            }
        }

        // 3. Cria o pedido
        const orderRes = await client.query(
            `INSERT INTO orders (user_id, items, total, status, shipping_address) 
             VALUES ($1, $2, $3, 'Pedido Confirmado', $4) RETURNING id`,
            [userId, JSON.stringify(items), total, JSON.stringify(shippingAddress)]
        );

        await client.query('COMMIT');

        res.status(201).json({
            message: 'Pedido realizado com sucesso!',
            orderId: 1000 + orderRes.rows[0].id
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Erro ao criar pedido:', err);
        res.status(500).json({ error: 'Erro ao salvar o pedido.' });
    } finally {
        client.release();
    }
});

app.get('/my-orders', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, items, total, status, shipping_address, created_at FROM orders WHERE user_id = $1 ORDER BY id DESC',
            [req.user.id]
        );

        const orders = rows.map(row => ({
            id: row.id,
            orderNumber: 1000 + row.id,
            items: row.items,
            total: parseFloat(row.total),
            status: row.status || 'Pedido Confirmado',
            shippingAddress: row.shipping_address,
            date: formatOrderDate(row.created_at)
        }));

        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao buscar pedidos.' });
    }
});

// Rota para o próprio cliente cancelar o pedido (permitido antes do envio)
app.put('/my-orders/:id/cancel', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const orderRes = await client.query(
            'SELECT id, status, items FROM orders WHERE id = $1 AND user_id = $2 FOR UPDATE',
            [req.params.id, req.user.id]
        );

        if (!orderRes.rows[0]) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Pedido não encontrado.' });
        }

        const order = orderRes.rows[0];
        if (order.status === 'Cancelado' || prevStatus === 'Entregue') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Este pedido já está cancelado.' });
        }

        if (order.status !== 'Pedido Confirmado' && order.status !== 'Em Separação') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Pedidos já enviados ou entregues não podem ser cancelados pelo site.' });
        }

        // Devolve os itens ao estoque
        for (const item of order.items) {
            await client.query('UPDATE products SET stock = stock + $1 WHERE name = $2', [item.quantity, item.name]);
        }

        await client.query("UPDATE orders SET status = 'Cancelado' WHERE id = $1", [order.id]);
        await client.query('COMMIT');

        res.json({ message: 'Pedido cancelado com sucesso e estoque estornado.' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Erro ao cancelar pedido.' });
    } finally {
        client.release();
    }
});

// ==========================================
// ROTAS DO PAINEL ADMINISTRATIVO
// ==========================================
app.get('/admin/orders', authenticateAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT o.id, o.items, o.total, o.status, o.shipping_address, o.created_at,
                   u.name AS customer_name, u.email AS customer_email, u.cpf AS customer_cpf
            FROM orders o
            JOIN users u ON o.user_id = u.id
            ORDER BY o.id DESC
        `);

        res.json(rows.map(r => ({
            id: r.id,
            orderNumber: 1000 + r.id,
            customerName: r.customer_name,
            customerEmail: r.customer_email,
            customerCpf: r.customer_cpf,
            items: r.items,
            total: parseFloat(r.total),
            status: r.status,
            shippingAddress: r.shipping_address,
            date: formatOrderDate(r.created_at)
        })));
    } catch (err) {
        res.status(500).json({ error: 'Erro ao listar pedidos administrativos.' });
    }
});

// Alterar status do pedido (devolve itens ao estoque se mudar para 'Cancelado')
// Alterar status do pedido (bloqueia alteração se já estiver Cancelado)
app.put('/admin/orders/:id/status', authenticateAdmin, async (req, res) => {
    const { status } = req.body;
    const validStatuses = ['Pedido Confirmado', 'Em Separação', 'Enviado', 'Entregue', 'Cancelado'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Status inválido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const currentOrder = await client.query('SELECT status, items FROM orders WHERE id = $1 FOR UPDATE', [req.params.id]);

        if (!currentOrder.rows[0]) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Pedido não encontrado.' });
        }

        const prevStatus = currentOrder.rows[0].status;
        const items = currentOrder.rows[0].items;

        if (prevStatus === 'Cancelado') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Pedidos cancelados não podem ter o status alterado.' });
        }

        if (status === 'Cancelado') {
            for (const item of items) {
                await client.query('UPDATE products SET stock = stock + $1 WHERE name = $2', [item.quantity, item.name]);
            }
        }

        await client.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
        await client.query('COMMIT');

        res.json({ message: `Status atualizado para "${status}".` });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Erro ao atualizar status.' });
    } finally {
        client.release();
    }
});

// Adicionar estoque a um produto
app.put('/admin/products/:id/stock', authenticateAdmin, async (req, res) => {
    const addQuantity = parseInt(req.body.addQuantity);
    if (isNaN(addQuantity) || addQuantity === 0) {
        return res.status(400).json({ error: 'Informe uma quantidade válida.' });
    }

    try {
        const { rows } = await pool.query(
            'UPDATE products SET stock = GREATEST(0, stock + $1) WHERE id = $2 RETURNING id, name, stock',
            [addQuantity, req.params.id]
        );
        if (!rows[0]) return res.status(404).json({ error: 'Produto não encontrado.' });
        res.json({ message: `Estoque atualizado: ${rows[0].name} agora tem ${rows[0].stock} un.`, product: rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao atualizar estoque.' });
    }
});

// Listar todas as contas cadastradas
app.get('/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, name, cpf, email, birth_date, is_admin FROM users ORDER BY id ASC'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao listar contas.' });
    }
});

// Excluir qualquer conta de usuário (Admin)
app.delete('/admin/users/:id', authenticateAdmin, async (req, res) => {
    const targetId = parseInt(req.params.id);
    if (targetId === req.user.id) {
        return res.status(400).json({ error: 'Você não pode excluir sua própria conta de administrador por aqui.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM orders WHERE user_id = $1', [targetId]);
        await client.query('DELETE FROM users WHERE id = $1', [targetId]);
        await client.query('COMMIT');
        res.json({ message: 'Conta e pedidos vinculados excluídos com sucesso.' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Erro ao excluir conta.' });
    } finally {
        client.release();
    }
});

app.listen(PORT, () => {
    console.log(`API da Belutti rodando na porta ${PORT}`);
});