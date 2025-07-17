const express = require('express');
const session = require('express-session');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const app = express();
const port = 8080//3001; //本地调试需使用8080

// 统一日志格式化函数
function logWithTimestamp(level, message, data = {}) {
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);
    const logData = {
        timestamp,
        level,
        message,
        ...data
    };
    
    console.log(JSON.stringify(logData, null, 2));
}

// 配置会话中间件
app.use(session({
    secret: 'your-secret-key', // 用于签名会话ID的密钥
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 会话有效期：24小时（毫秒）
      secure: process.env.NODE_ENV === 'production', // 是否仅 HTTPS 传输 Cookie
      httpOnly: true, // 防止 XSS 攻击
    } // 开发环境使用HTTP，生产环境建议设置为true（HTTPS）
  }));

// 验证 Token 并确保 session 数据完整
async function isValidToken(req, res) {
    const token = req.query?.token || req?.token || req.body?.token || req.session?.token;
    const redirectUrl = 'https://helport.ai/oauth/login?app=console&redirect_uri=http://localhost:8080';
    //const redirectUrl = 'https://helport.ai/oauth/login?app=console&redirect_uri=https://kbf.helport.ai';
    
    if (!token) {
        logWithTimestamp('WARN', '未提供Token', { token });
        res.redirect(redirectUrl);
        return false;
    }
    
    try {
        // 1. 验证Token有效性（用户详情接口）
        const authData = JSON.stringify({ token });
        const authConfig = {
            method: 'post',
            url: 'https://helport.ai/api/auth/getUserDetailByToken',
            headers: { 'Content-Type': 'application/json' },
            data: authData
        };
        
        const authResponse = await axios(authConfig);
        const userData = authResponse.data?.data;
        
        if (!userData) {
            throw new Error('用户详情接口返回无效数据');
        }
        
        // 2. 保存用户信息到session
        req.session.client_id = userData.tenantId;
        req.session.client_name = userData.tenantName;
        req.session.token = token;
        
        // 3. 获取业务产品列表（失败时直接视为Token失效，触发重定向）
        const bizConfig = {
            method: 'get',
            url: 'https://helport.ai/api/dolphin-ai/user/biz/product',
            headers: { 'Authorization': `Bearer ${token}` }
        };
        
        const bizResponse = await axios(bizConfig);
        req.session.data = bizResponse.data?.data;
        
        logWithTimestamp('INFO', 'Token验证成功', { 
            client_id: req.session.client_id,
            client_name: req.session.client_name,
            bizCount: req.session.data?.length || 0
        });
        
        return true;
    } catch (error) {
        // 清除失效的Token
        req.session.token = '';
        
        // 记录错误详情
        const errorInfo = {
            message: error.message,
            status: error.response?.status,
            token: token?.substring(0, 10) + '...' // 部分显示Token，保护安全
        };
        logWithTimestamp('ERROR', 'Token验证失败', errorInfo);
        
        // 无论何种错误，统一重定向到登录页
        res.redirect(redirectUrl);
        return false;
    }
}

// 验证中间件
const verifyToken = async (req, res, next) => {
    const isValid = await isValidToken(req, res);
    if (isValid) {
        next();
    }
};

// 获取租户信息接口
app.get('/user/client_id', async (req, res) => {
    const clientInfo = {
        name: req.session.client_name,
        id: req.session.client_id
    };
    
    logWithTimestamp('INFO', '获取租户信息', clientInfo);
    
    if (!clientInfo.id) {
        return res.status(401).json({ error: '无法获取租户信息，请重新登录' });
    }
    
    return res.json([clientInfo]);
});

// 根据token获取业务名称列表及产品列表（简化版，因为验证逻辑已移至isValidToken）
app.get('/user/biz/product', async (req, res) => {
    try {
        // 直接返回 session 中已缓存的数据
        if (req.session.data) {
            logWithTimestamp('INFO', '从缓存获取业务和产品列表成功', { 
                count: req.session.data?.length || 0
            });
            return res.json(req.session.data);
        }
        
        // 如果缓存中没有数据（可能是其他路由调用），重新获取
        const config = {
            method: 'get',
            url: 'https://helport.ai/api/dolphin-ai/user/biz/product',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${req.session.token}`
            },
        };

        const response = await axios(config);
        req.session.data = response.data?.data;
        
        logWithTimestamp('INFO', '重新获取业务和产品列表成功', { 
            count: req.session.data?.length || 0
        });
        
        res.json(req.session.data);
    } catch (error) {
        req.session.token = '';
        logWithTimestamp('ERROR', '获取业务和产品列表失败', { error: error.message });
        res.status(500).json({ error: '获取业务和产品列表失败' });
    }
});

//所有请求操作都需要进行验证！
app.use('/', verifyToken);

// 允许跨域请求
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// 提供静态文件服务
app.use(express.static(path.join(__dirname)));

// 设置请求体大小限制为 50MB
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
  logWithTimestamp('INFO', '创建上传目录', { directory: uploadDir });
}
// 配置 multer 存储选项
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, uploadDir); // 指定文件存储的目录
    },
    filename: function (req, file, cb) {
      cb(null, file.originalname);
    },
  });
  
const fileFilter = (req, file, callback) => {
    // 转换文件名编码
    file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf-8');
    callback(null, true);
  };
  
const upload = multer({ storage: storage, fileFilter: fileFilter });

const BASE_URL = "https://agent.helport.ai/v1"

const KB_API_KEY = "dataset-Wui7Wlhj6jtY10rW0wXjoUqo" //知识库操作API

const CKB_API_KEY = "app-8eO9ykobHpIHZ9dGicfdRBii" //根据pdf文件创建知识库
const CQKB_API_KEY = "app-grIDUxUxkAOPApD8kAL21VIO" //创建空问答知识库

const CGQA_API_KEY = "app-FHPDSyg7cYeczAVFLfbHLTr0" //chunk生成问答
const QKB_API_KEY = "app-bJNfYsxxPt8kIOdd4bf56fFR" //查询知识库
const FA_API_KEY = "app-0AoAfHqk1hcmEpZCyuFQE2QA"  //问题找答案

const SA_API_KEY = "app-TmHcFKTvau3Z3nbYJkSkUn7" // 会话分析

const SA_CQL_API_KEY = "app-OhAcbxsrEQmSN3w3AFYxEK1V" //获取会话及问题列表
const SA_SCC_API_KEY = "app-D971pWeySqZ5a39JSF4M7rQq" //获取单个会话内容  
const SA_SCS_API_KEY = "app-7RhFGtsT1qmSTa0rvvcTlXme"  //单个会话分析

//问答生成：创建知识库上传pdf
app.post('/api/files/upload_pdf', upload.single('file'), async (req, res) => {
    if (!req.file) {
      logWithTimestamp('WARN', '文件上传失败', { reason: '未提供文件' });
      return res.status(400).send('No file uploaded.');
    }
  
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    logWithTimestamp('DEBUG', '文件上传路径', { filePath });
    const fileStream = fs.createReadStream(filePath);

    try {
        const response = await axios.post(`${BASE_URL}/files/upload`, {
            file: fileStream,
            user: req.user
          }, {
            headers: {
                'Authorization': `Bearer ${CKB_API_KEY}`, //根据pdf问答生成问答
                'Content-Type': 'multipart/form-data',
            }
        });

        // 删除本地临时文件
        fs.unlinkSync(filePath);

        const data = response.data;
        logWithTimestamp('INFO', '文件上传成功', { 
            filename: req.file.originalname,
            upload_id: data.id || '未返回ID'
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '文件上传失败', { 
            filename: req.file.originalname,
            error: error.message
        });
        if (error.response) {
            logWithTimestamp('ERROR', 'API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});
// 问答生成: 创建知识库
app.post('/api/qa/create_knowledge', async (req, res) => {
    const body = req.body;
    
    // 结构化请求日志
    logWithTimestamp('INFO', '创建知识库请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${CKB_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status !== 200) {
            throw new Error(`HTTP错误: ${response.status}`);
        }

        // 结构化成功日志
        logWithTimestamp('INFO', '创建知识库成功', { 
            status_code: response.status,
            event: response.data.event || '未知'
        });
        
        res.json(response.data);
    } catch (error) {
        // 结构化错误日志
        if (error.response) {
            logWithTimestamp('ERROR', '创建知识库失败', { 
                status_code: error.response.status,
                message: error.response.data.message || '无详情'
            });
        } else {
            logWithTimestamp('ERROR', '创建知识库异常', { message: error.message });
        }
        
        res.status(500).json({ error: error.message });
    }
});

// 问答生成: 创建问答知识库
app.post('/api/qa/create_qa_knowledge', async (req, res) => {
    const body = req.body;
    
    // 结构化请求日志
    logWithTimestamp('INFO', '创建问答知识库请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${CQKB_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status !== 200) {
            throw new Error(`HTTP错误: ${response.status}`);
        }

        // 结构化成功日志
        logWithTimestamp('INFO', '创建问答知识库成功', { 
            status_code: response.status,
            event: response.data.event || '未知'
        });
        
        res.json(response.data);

    } catch (error) {
        // 结构化错误日志
        if (error.response) {
            logWithTimestamp('ERROR', '创建问答知识库失败', { 
                status_code: error.response.status,
                message: error.response.data.message || '无详情'
            });
        } else {
            logWithTimestamp('ERROR', '创建问答知识库异常', { message: error.message });
        }
        
        res.status(500).json({ error: error.message });
    }
});


//问答生成: 生成问答-单个chunk生成问答
app.post('/api/qa/generate', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '生成问答请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${CGQA_API_KEY}`, //根据单个chunk生成问答
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '生成问答成功', { 
            status_code: response.status,
            qa_count: data.response?.data?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '生成问答失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '生成问答API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//问答生成: 根据问题检索获得答案
app.post('/api/qa/findAnswer', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '问题检索请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${FA_API_KEY}`, //根据问题从知识库检索答案
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '问题检索成功', { 
            status_code: response.status,
            answer_count: data.response?.data?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '问题检索失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '问题检索API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//问答查询,输出所有的问答，需要分页
app.post('/api/qa/query', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '问答查询请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${QKB_API_KEY}`, //根据知识库名称导出知识库问答
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '问答查询成功', { 
            status_code: response.status,
            qa_count: data.response?.data?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '问答查询失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '问答查询API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

// 获取所有知识库
app.get('/api/datasets', async (req, res) => {
    const queryParams = req.query; // 获取URL查询参数
    
    // 结构化日志：记录请求信息
    logWithTimestamp('INFO', '获取知识库列表请求', { query_params: queryParams });

    try {
        const response = await axios.get(`${BASE_URL}/datasets`, {
            params: queryParams, // 将查询参数传递给axios
            headers: {
                'Authorization': `Bearer ${KB_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        // 验证响应状态
        if (response.status !== 200) {
            throw new Error(`获取知识库列表失败 | HTTP状态码: ${response.status}`);
        }

        const data = response.data;
        
        // 有针对性的输出：记录关键响应指标
        const datasetCount = data.total || 0;
        logWithTimestamp('INFO', '获取知识库列表成功', { 
            status_code: response.status,
            dataset_count: datasetCount
        });
        
        res.json({data});

    } catch (error) {
        // 结构化错误日志：区分客户端错误和服务端错误
        if (error.response) {
            logWithTimestamp('ERROR', '获取知识库列表失败', { 
                status_code: error.response.status,
                message: error.response.data.message || '无详情'
            });
        } else {
            logWithTimestamp('ERROR', '获取知识库列表异常', { message: error.message });
        }
        
        res.status(500).json({
            error: '获取知识库列表失败',
            details: error.message
        });
    }
});

// 获取知识库文档
app.get(`/api/datasets/:datasetId/documents`, async (req, res) => {
    const { datasetId } = req.params;
    const queryParams = req.query;
    
    // 结构化日志：记录请求信息
    logWithTimestamp('INFO', '获取文档列表请求', { 
        dataset_id: datasetId,
        query_params: queryParams
    });

    try {
        const response = await axios.get(`${BASE_URL}/datasets/${datasetId}/documents`, {
            params: queryParams,
            headers: {
                'Authorization': `Bearer ${KB_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        // 验证响应状态
        if (response.status !== 200) {
            throw new Error(`获取文档列表失败 | HTTP状态码: ${response.status}`);
        }

        const data = response.data;
        
        // 有针对性的输出：记录关键响应指标
        const documentCount = data.documents?.total || 0;
        logWithTimestamp('INFO', '获取文档列表成功', { 
            dataset_id: datasetId,
            status_code: response.status,
            document_count: documentCount
        });
        
        res.json(data);
    } catch (error) {
        // 结构化错误日志：区分客户端错误和服务端错误
        if (error.response) {
            logWithTimestamp('ERROR', '获取文档列表失败', { 
                dataset_id: datasetId,
                status_code: error.response.status,
                message: error.response.data.message || '无详情'
            });
        } else {
            logWithTimestamp('ERROR', '获取文档列表异常', { 
                dataset_id: datasetId,
                message: error.message
            });
        }
        
        res.status(500).json({ 
            error: '获取文档列表失败',
            details: error.message 
        });
    }
});

// 获取文档分段
app.get(`/api/datasets/:datasetId/documents/:documentId/segments`, async (req, res) => {
    const { datasetId, documentId } = req.params;
    const queryParams = req.query;
    
    // 结构化日志：记录请求信息
    logWithTimestamp('INFO', '获取文档分段请求', { 
        dataset_id: datasetId,
        document_id: documentId,
        query_params: queryParams
    });

    try {
        const response = await axios.get(
            `${BASE_URL}/datasets/${datasetId}/documents/${documentId}/segments`,{
                params: queryParams,
                headers: {
                    'Authorization': `Bearer ${KB_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        // 验证响应状态
        if (response.status !== 200) {
            throw new Error(`获取文档分段失败 | HTTP状态码: ${response.status}`);
        }

        const data = response.data;
        
        // 有针对性的输出：记录关键响应指标
        const segmentsCount = data.chunks?.length || 0;
        const totalSegments = data.total || 0;
        logWithTimestamp('INFO', '获取文档分段成功', { 
            dataset_id: datasetId,
            document_id: documentId,
            status_code: response.status,
            current_segment_count: segmentsCount,
            total_segment_count: totalSegments
        });
        
        res.json(data);
    } catch (error) {
        // 结构化错误日志：区分客户端错误和服务端错误
        if (error.response) {
            logWithTimestamp('ERROR', '获取文档分段失败', { 
                dataset_id: datasetId,
                document_id: documentId,
                status_code: error.response.status,
                message: error.response.data.message || '无详情'
            });
        } else {
            logWithTimestamp('ERROR', '获取文档分段异常', { 
                dataset_id: datasetId,
                document_id: documentId,
                message: error.message
            });
        }
        
        res.status(500).json({ 
            error: '获取文档分段失败',
            details: error.message 
        });
    }
});

// 会话分析 会话ids及问题列表
app.post('/api/session_ids', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '获取会话ID及问题列表请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${SA_CQL_API_KEY}`, //会话及问题列表
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '获取会话ID及问题列表成功', { 
            status_code: response.status,
            session_count: data.response?.data?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '获取会话ID及问题列表失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '获取会话ID及问题列表API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//会话分析：单个会话
app.post('/api/single_session', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '获取单个会话请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${SA_SCC_API_KEY}`, //会话分析
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '获取单个会话成功', { 
            status_code: response.status,
            session_id: body.session_id
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '获取单个会话失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '获取单个会话API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//会话分析：单个会话分析
app.post('/api/session_analysis', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '单个会话分析请求', { 
        body: body || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${SA_SCS_API_KEY}`, //单个会话分析
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '单个会话分析成功', { 
            status_code: response.status,
            session_id: body.session_id
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '单个会话分析失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '单个会话分析API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//问答生成：上传问题列表xlsx找答案(弃用)
app.post('/api/files/upload_xlsx', upload.single('file'), async (req, res) => {
    if (!req.file) {
      logWithTimestamp('WARN', 'XLSX文件上传失败', { reason: '未提供文件' });
      return res.status(400).send('No file uploaded.');
    }
  
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    logWithTimestamp('DEBUG', 'XLSX文件上传路径', { filePath });
    const fileStream = fs.createReadStream(filePath);

    try {
        const response = await axios.post('http://agent.helport.ai/v1/files/upload', {
            file: fileStream,
            user: 'abc-123', // 添加其他需要的参数
          }, {
            headers: {
                'Authorization': 'Bearer app-bXNQJjnZ1Z72KOvRrl5hFJAV', 
                'Content-Type': 'multipart/form-data',
            }
        });

        // 删除本地临时文件
        fs.unlinkSync(filePath);

        const data = response.data;
        logWithTimestamp('INFO', 'XLSX文件上传成功', { 
            filename: req.file.originalname,
            upload_id: data.id || '未返回ID'
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', 'XLSX文件上传失败', { 
            filename: req.file.originalname,
            error: error.message
        });
        if (error.response) {
            logWithTimestamp('ERROR', 'XLSX文件上传API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//报表生成：上传CSV文件（弃用）
app.post('/api/files/upload_csv', upload.single('file'), async (req, res) => {
    if (!req.file) {
      logWithTimestamp('WARN', 'CSV文件上传失败', { reason: '未提供文件' });
      return res.status(400).send('No file uploaded.');
    }
  
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    logWithTimestamp('DEBUG', 'CSV文件上传路径', { filePath });
    const fileStream = fs.createReadStream(filePath);

    try {
        const response = await axios.post('http://34.19.122.203:8503/v1/files/upload', {
            file: fileStream,
            user: 'abc-123', // 添加其他需要的参数
          }, {
            headers: {
                'Authorization': 'Bearer app-JERPmCZXLzsvc0PWBZ4jGxnQ', //导入CSV文件到数据库
                'Content-Type': 'multipart/form-data',
            }
        });

        // 删除本地临时文件
        fs.unlinkSync(filePath);

        const data = response.data;
        logWithTimestamp('INFO', 'CSV文件上传成功', { 
            filename: req.file.originalname,
            upload_id: data.id || '未返回ID'
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', 'CSV文件上传失败', { 
            filename: req.file.originalname,
            error: error.message
        });
        if (error.response) {
            logWithTimestamp('ERROR', 'CSV文件上传API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

// 会话分析（弃用）
app.post('/api/session', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '会话分析请求', { 
        start_time: body.start_time || '未提供',
        end_time: body.end_time || '未提供'
    });

    try {
        const response = await axios.post(`${BASE_URL}/workflows/run`, body, {
            headers: {
                'Authorization': `Bearer ${SA_API_KEY}`, //会话分析
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '会话分析成功', { 
            status_code: response.status,
            session_count: data.response?.data?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '会话分析失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '会话分析API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//报表生成：导入CSV文件（弃用）
app.post('/api/chart/csv_to_db', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', 'CSV导入数据库请求', { 
        table_name: body.table_name || '未提供',
        file_id: body.file_id || '未提供'
    });

    try {
        const response = await axios.post('http://34.19.122.203:8503/v1/workflows/run', body, {
            headers: {
                'Authorization': 'Bearer app-JERPmCZXLzsvc0PWBZ4jGxnQ', //导入CSV文件到数据库
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', 'CSV导入数据库成功', { 
            status_code: response.status,
            task_id: data.task_id || '未返回'
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', 'CSV导入数据库失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', 'CSV导入数据库API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

//报表生成：大模型数据分析（弃用）
app.post('/api/chart/chat', async (req, res) => {
    const body = req.body; // 获取请求体
    logWithTimestamp('DEBUG', '大模型数据分析请求', { 
        query: body.query?.substring(0, 50) || '未提供'
    });

    try {
        const response = await axios.post('http://34.19.122.203:8503/v1/chat-messages', body, {
            headers: {
                'Authorization': 'Bearer app-EaF6Bawwm82nFdZ6dZz4zcnf', //大模型数据分析
                'Content-Type': 'application/json'
            }
        });

        // 检查响应状态码
        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = response.data;
        logWithTimestamp('INFO', '大模型数据分析成功', { 
            status_code: response.status,
            result_count: data.results?.length || 0
        });
        res.json(data);
    } catch (error) {
        logWithTimestamp('ERROR', '大模型数据分析失败', { error: error.message });
        if (error.response) {
            logWithTimestamp('ERROR', '大模型数据分析API响应错误', { 
                status: error.response.status,
                data: error.response.data
            });
        }
        res.status(500).json({ error: error.message });
    }
});

// 默认加载 index.html
app.get('/', (req, res) => {
    logWithTimestamp('INFO', '首页请求', { ip: req.ip });
    res.sendFile(path.join(__dirname, `index.html?token=${cur_token}`));
});

app.listen(port, () => {
    logWithTimestamp('INFO', '服务器启动成功', { 
        port,
        environment: process.env.NODE_ENV || 'development'
    });
    console.log(`Server running at http://localhost:${port}/`);
});