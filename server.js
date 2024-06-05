const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const path = require('path');
const authorizeAdmin = require('./middleware/authorizeAdmin');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'qna_app'
});

db.connect(err => {
    if (err) {
        throw err;
    }
    console.log('MySQL connected...');
});

// Function to save token
const saveToken = (userId, token) => {
    return new Promise((resolve, reject) => {
        db.query('INSERT INTO sessions (user_id, token) VALUES (?, ?)', [userId, token], (err, result) => {
            if (err) {
                return reject(err);
            }
            resolve(result);
        });
    });
};

// Function to verify token
const verifyToken = (token) => {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM sessions WHERE token = ?', [token], (err, results) => {
            if (err) {
                return reject(err);
            }
            if (results.length === 0) {
                return reject(new Error('Invalid token'));
            }
            resolve(results[0]);
        });
    });
};

// API endpoints

// Registration
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Error hashing password', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], (err, result) => {
            if (err) {
                console.error('Error inserting user into database', err);
                return res.status(500).json({ message: 'Internal server error' });
            }
            res.sendStatus(201);
        });
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.sendStatus(401);
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.sendStatus(401);

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, 'secretkey', { expiresIn: '1h' });
        await saveToken(user.id, token);
        res.json({ token });
    });
});

// Authentication middleware
const authenticate = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    const token = authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    try {
        const session = await verifyToken(token);
        jwt.verify(token, 'secretkey', (err, decoded) => {
            if (err) return res.sendStatus(401);
            req.user = decoded;
            next();
        });
    } catch (err) {
        res.sendStatus(401);
    }
};

// Fetch all questions with usernames and answer count
app.get('/api/questions', (req, res) => {
    const query = `
        SELECT q.*, u.username, 
        (SELECT COUNT(*) FROM answers WHERE question_id = q.id) as answers_count
        FROM questions q
        JOIN users u ON q.user_id = u.id
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching questions:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.json(results);
    });
});

// Fetch all categories
app.get('/api/categories', (req, res) => {
    db.query('SELECT * FROM categories', (err, results) => {
        if (err) {
            console.error('Error fetching categories:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.json(results);
    });
});


// Fetch question details along with answers
app.get('/api/questions/:id', (req, res) => {
    const questionId = req.params.id;

    const questionQuery = `
        SELECT q.*, u.username 
        FROM questions q 
        JOIN users u ON q.user_id = u.id 
        WHERE q.id = ?
    `;

    db.query(questionQuery, [questionId], (err, questionResults) => {
        if (err) {
            console.error('Error fetching question:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (questionResults.length === 0) {
            return res.status(404).json({ message: 'Question not found' });
        }

        const question = questionResults[0];

        const answersQuery = `
            SELECT a.*, IFNULL(SUM(v.vote = 1), 0) AS upvotes, IFNULL(SUM(v.vote = -1), 0) AS downvotes 
            FROM answers a 
            LEFT JOIN votes v ON a.id = v.answer_id 
            WHERE a.question_id = ? 
            GROUP BY a.id
        `;

        db.query(answersQuery, [questionId], (err, answerResults) => {
            if (err) {
                console.error('Error fetching answers:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            res.json({
                question,
                answers: answerResults
            });
        });
    });
});

// Submit an answer to a question
app.post('/api/questions/:id/answers', authenticate, (req, res) => {
    const questionId = req.params.id;
    const { content } = req.body;
    const userId = req.user.id;

    db.query('INSERT INTO answers (question_id, user_id, content) VALUES (?, ?, ?)', [questionId, userId, content], (err, result) => {
        if (err) {
            console.error('Error submitting answer:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        res.sendStatus(201);
    });
});

// Vote on an answer
app.post('/api/answers/:id/vote', authenticate, (req, res) => {
    const answerId = req.params.id;
    const { vote } = req.body; // 1 for upvote, -1 for downvote
    const userId = req.user.id;

    db.query('SELECT * FROM votes WHERE answer_id = ? AND user_id = ?', [answerId, userId], (err, results) => {
        if (err) {
            console.error('Error fetching vote:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
            const existingVote = results[0].vote;
            if (existingVote === vote) {
                // User has already voted in the same way, remove the vote (unvote)
                db.query('DELETE FROM votes WHERE answer_id = ? AND user_id = ?', [answerId, userId], (err, result) => {
                    if (err) {
                        console.error('Error deleting vote:', err);
                        return res.status(500).json({ message: 'Internal server error' });
                    }
                    res.sendStatus(200);
                });
            } else {
                // User has voted differently, update the vote
                db.query('UPDATE votes SET vote = ? WHERE answer_id = ? AND user_id = ?', [vote, answerId, userId], (err, result) => {
                    if (err) {
                        console.error('Error updating vote:', err);
                        return res.status(500).json({ message: 'Internal server error' });
                    }
                    res.sendStatus(200);
                });
            }
        } else {
            // User has not voted, insert a new vote
            db.query('INSERT INTO votes (answer_id, user_id, vote) VALUES (?, ?, ?)', [answerId, userId, vote], (err, result) => {
                if (err) {
                    console.error('Error inserting vote:', err);
                    return res.status(500).json({ message: 'Internal server error' });
                }
                res.sendStatus(201);
            });
        }
    });
});

// Add a new question
app.post('/api/questions', authenticate, (req, res) => {
    const { title, category_id, description } = req.body;
    const user_id = req.user.id;
    db.query('INSERT INTO questions (title, category_id, description, user_id) VALUES (?, ?, ?, ?)', [title, category_id, description, user_id], (err, result) => {
        if (err) {
            console.error('Error inserting question:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.sendStatus(201);
    });
});

// Update a question
app.put('/api/questions/:id', authenticate, (req, res) => {
    const questionId = req.params.id;
    const { title, category_id, description } = req.body;
    const userId = req.user.id;

    // Check if the user is the owner of the question or an admin
    db.query('SELECT * FROM questions WHERE id = ?', [questionId], (err, results) => {
        if (err) {
            console.error('Error fetching question:', err);
            return res.status(500).json({ message: 'Internal server error', error: err });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Question not found' });
        }

        const question = results[0];
        if (question.user_id !== userId && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden' });
        }

        // Update the question
        db.query('UPDATE questions SET title = ?, category_id = ?, description = ?, edited_at = NOW() WHERE id = ?', [title, category_id, description, questionId], (err, result) => {
            if (err) {
                console.error('Error updating question:', err);
                return res.status(500).json({ message: 'Internal server error', error: err });
            }

            res.sendStatus(200);
        });
    });
});

// Delete a question
app.delete('/api/questions/:id', authenticate, (req, res) => {
    const questionId = req.params.id;
    const userId = req.user.id;

    // Check if the user is the owner of the question or an admin
    db.query('SELECT * FROM questions WHERE id = ?', [questionId], (err, results) => {
        if (err) {
            console.error('Error fetching question:', err);
            return res.status(500).json({ message: 'Internal server error', error: err });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Question not found' });
        }

        const question = results[0];
        if (question.user_id !== userId && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden' });
        }

        // Delete all votes related to the answers of the question
        db.query('DELETE v FROM votes v INNER JOIN answers a ON v.answer_id = a.id WHERE a.question_id = ?', [questionId], (err, result) => {
            if (err) {
                console.error('Error deleting votes:', err);
                return res.status(500).json({ message: 'Internal server error', error: err });
            }

            // Delete all answers related to the question
            db.query('DELETE FROM answers WHERE question_id = ?', [questionId], (err, result) => {
                if (err) {
                    console.error('Error deleting answers:', err);
                    return res.status(500).json({ message: 'Internal server error', error: err });
                }

                // Delete the question
                db.query('DELETE FROM questions WHERE id = ?', [questionId], (err, result) => {
                    if (err) {
                        console.error('Error deleting question:', err);
                        return res.status(500).json({ message: 'Internal server error', error: err });
                    }

                    res.sendStatus(200);
                });
            });
        });
    });
});

app.get('/api/admin', authenticate, authorizeAdmin, (req, res) => {
    res.json({ message: 'Welcome to the admin panel' });
});

// Serve static assets if in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static('qna_frontend/build'));

    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'qna_frontend', 'build', 'index.html'));
    });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
