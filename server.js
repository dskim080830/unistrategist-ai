require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const OpenAI = require('openai');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const axios = require('axios');
const app = express();

const UNIV_FILE_MAP = {
    "서울대학교" : "https://drive.google.com/file/d/1CNtmjhLL4nDoLjS0uOuqYsrJSITxsG8b/preview",
    "연세대학교" : "https://drive.google.com/file/d/1hucXBDJijeNwO6c53_xy-MoC2V9tOLre/preview",
    "고려대학교" : "https://drive.google.com/file/d/1m_YitavEN6xyoDmcH5ATwyF0zB_8D4PJ/preview",
    "서강대학교" : "https://drive.google.com/file/d/1IKctjHoq15yHue069dpEphYXJqrLSr_Q/preview",
    "성균관대학교" : "https://drive.google.com/file/d/17r_G4UOW_c3r5rdchKB9uyd2Xd4os_Zj/preview",
    "한양대학교" : "https://drive.google.com/file/d/1VSnKOas4XCQN-LP6eI10ReoSfBk9CEiB/preview",
    "중앙대학교" : "https://drive.google.com/file/d/11QUTYjKWWHXkzZVH_pzT9KLNCgUtVm0R/preview",
    "경희대학교" : "https://drive.google.com/file/d/1x4gYtMHu4DuYEVwZa2UEqBHXFpvUjQF6/preview",
    "한국외국어대학교" : "https://drive.google.com/file/d/1VQxeIBm8IdniB-Pn0B_a5K1dmyiJtxtG/preview",
    "서울시립대학교" : "https://drive.google.com/file/d/1bUJLf2XHiBIOb2wh5mzggCvZ8lQia1Dr/preview",
    "이화여자대학교" : "https://drive.google.com/file/d/1_spcNTAfhRaImDHQ5YwoU_jcw4F6FFvh/preview",
    "건국대학교" : "https://drive.google.com/file/d/1lFZfpj9CoTHX6RNhN4g5Bj2JmDakzmWI/preview",
    "동국대학교" : "https://drive.google.com/file/d/18WN2JJ10Li1fIs3QsDJjxRWFkBUpbLWn/preview",
    "홍익대학교" : "https://drive.google.com/file/d/1fjRiLTClbh2EXSNprib0ytRTlGa0dOWd/preview",
    "숙명여자대학교" : "https://drive.google.com/file/d/1BBVvnAbBTz3NV82_AJp7kLqRnYg0akUA/preview",
    "국민대학교" : "https://drive.google.com/file/d/1f5It2i3rVEk09ZQu7TnquEsW2w3ndRTc/preview",
    "숭실대학교" : "https://drive.google.com/file/d/1ZKsS-zbDkc8PmgAUQO1ozgmTkTLpqZyi/preview",
    "세종대학교" : "https://drive.google.com/file/d/1CpIXRWBLGfrFmrBZcXdYEjfZu2Oj6nle/preview",
    "단국대학교" : "https://drive.google.com/file/d/19SPp8Zs9i3Adl1mEV3paJzB05uR3nfmJ/preview",
    "KAIST" : "https://drive.google.com/file/d/1u4DvemUX-iqMKMIjAy2uHGVwaG5xwL8r/preview",
    "POSTECH": "https://drive.google.com/file/d/1Vqn-kITH7VDkki_cdGoWLTDzKje1Lq2c/preview",
    "서울교육대학교" : "https://drive.google.com/file/d/1rWIlak0o3eWPy60XlOc7hGlaPJ00jC__/preview",
    "서울과학기술대학교" : "https://drive.google.com/file/d/1kG16tlAaEZcdUEMdSIceyecAAwBqEYbX/preview",
    '육군사관학교' : 'https://drive.google.com/file/d/19W2Fpo1SBCkVDfDCRSI9HjWE3weUsN3Z/preview',
    '광운대학교' : 'https://drive.google.com/file/d/1CssecwLhgpZ14X2zmJ9LRMqcpuBdUctG/preview',
    '명지대학교' : 'https://drive.google.com/file/d/11C7L0UELFrtsA4G6icUL4Wn5bCwMGsoQ/preview',
    '상명대학교' : 'https://drive.google.com/file/d/1k4WYO9RgfhNw6dft7tdZwe_MVAhPs--j/preview',
    '덕성여자대학교' : 'https://drive.google.com/file/d/1qIp4MOZ7Vzr0EIi-nCIDdxwCPOaOXzfx/preview',
    '동덕여자대학교' : 'https://drive.google.com/file/d/1_NueMcZwLx-fVDLDr0ve9z9juZ2CDxWI/preview',
    "가천대학교" : "https://drive.google.com/file/d/1ELpGFM94YMnKwwHwpTXeBesENdl68h8O/preview",
    "인하대학교" : "https://drive.google.com/file/d/1X1UEk_FwG99Bwsa81POos-aSX7M8AryW/preview",
    "인천대학교" : "https://drive.google.com/file/d/130pK_8QD3xuZK-HtzdY1sbczAvl9d0Kq/preview",
    "한성대학교": "https://drive.google.com/file/d/1gVbNkb7JAJP-0z9j0VKOt7Z_ehGo-992/preview"
};

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'unistrategist_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } 
}));

app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.use(express.static(__dirname, { index: false }));


app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'home.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/analysis', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/special.html', (req, res) => res.sendFile(path.join(__dirname, 'special.html')));
app.get('/essay.html', (req, res) => res.sendFile(path.join(__dirname, 'essay.html')));

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, // 또는 process.env.DB_PASS (본인이 쓴 변수명 확인!)
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false } // <--- 필수!
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        
        const [rows] = await db.query(
            "SELECT * FROM users WHERE username = ?",
            [username]
        );

        if (rows.length === 0) {
            return res.send("<script>alert('존재하지 않는 계정입니다.'); history.back();</script>");
        }

        const user = rows[0];
        const pwMatch = await bcrypt.compare(password, user.password);

        if (!pwMatch) {
            return res.send("<script>alert('비밀번호가 올바르지 않습니다.'); history.back();</script>");
        }

        
        req.session.user = {
            id: user.id,
            username: user.username,
            name: user.name,
            role: "user"
        };

        res.redirect("/");

    } catch (err) {
        console.error(err);
        res.status(500).send("<script>alert('로그인 시스템 오류'); history.back();</script>");
    }
});

app.get('/school-search', async (req, res) => {
    const query = req.query.q;
    const url = `https://open.neis.go.kr/hub/schoolInfo?Type=json&SCHUL_NM=${encodeURI(query)}`;

    try {
        const response = await axios.get(url);
        const data = response.data;

        if (data.schoolInfo && data.schoolInfo[1] && data.schoolInfo[1].row) {
            const result = data.schoolInfo[1].row.map(item => ({
                SCHUL_NM: item.SCHUL_NM,           
                LCTN_SC_NM: item.LCTN_SC_NM,       
                SD_SCHUL_CODE: item.SD_SCHUL_CODE, 
                ATPT_OFCDC_SC_CODE: item.ATPT_OFCDC_SC_CODE 
            }));
            res.json(result);
        } else {
            res.json([]);
        }
    } catch (error) {
        console.error("NEIS API Error:", error);
        res.status(500).json({ error: "학교 검색 실패" });
    }
});


app.post("/signup", async (req, res) => {
    try {
        const { username, password, name, birthdate, grade, school_name, school_code, consent } = req.body;
        
        console.log("👉 회원가입 요청 데이터:", req.body);

        if(!username || !password || !name || !school_code) {
             return res.send("<script>alert('학교를 검색 목록에서 반드시 클릭해서 선택해주세요.'); history.back();</script>");
        }

        const hashed = await bcrypt.hash(password, 10);
        
        const consentValue = consent ? 1 : 0;

        await db.query(
            `INSERT INTO users (username, password, name, birthdate, grade, school_name, school_code, consent) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [username, hashed, name, birthdate, grade, school_name, school_code, consentValue]
        );

        res.send("<script>alert('회원가입 완료! 로그인해주세요.'); location.href='/login.html';</script>");

    } catch (err) {
        console.error("🔥 회원가입 에러:", err);
        res.status(500).send(`<script>alert('오류 발생: ${err.sqlMessage || "시스템 에러"}'); history.back();</script>`);
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});

app.get("/api/session", (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, name: req.session.user.name, username: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});

function extractRelevantPart(fullText, keyword) {
    if (!keyword || keyword.trim().length < 2) return fullText.slice(0, 15000);
    const lowerText = fullText.toLowerCase();
    const lowerKeyword = keyword.toLowerCase();
    const idx = lowerText.indexOf(lowerKeyword);
    if (idx === -1) return fullText.slice(0, 15000);
    return fullText.slice(Math.max(0, idx - 200), idx + 2500);
}

function getGoogleDriveDownloadUrl(previewUrl) {
    const id = previewUrl.split('/d/')[1].split('/')[0];
    return `https://drive.google.com/uc?export=download&id=${id}`;
}

// ---------------- AI 분석 API (수정됨) ----------------
app.post('/api/history', async (req, res) => {
  req.setTimeout(300000); // 5분 타임아웃

  try {
    const { text, analysisType, targetUniv, targetMajor, targetType } = req.body;
    
    if (!text) return res.status(400).json({ error: '분석할 텍스트가 없습니다.' });

    // 1. 모집요강 PDF 읽기
    let admissionGuideText = "해당 대학의 구체적인 모집요강 파일이 서버에 없습니다. 일반적인 입시 기준으로 분석합니다.";
    
    if (targetUniv && UNIV_FILE_MAP[targetUniv]) {
        const pdfUrl = UNIV_FILE_MAP[targetUniv];
        const downloadUrl = getGoogleDriveDownloadUrl(pdfUrl);

        try {
            console.log(`Downloading PDF for ${targetUniv}: ${downloadUrl}`);
            const response = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
            const dataBuffer = Buffer.from(response.data);
            const pdfData = await pdfParse(dataBuffer);
            
            if (targetType) {
                admissionGuideText = extractRelevantPart(pdfData.text, targetType);
            } else {
                admissionGuideText = pdfData.text.slice(0, 15000);
            }
            
        } catch (pdfErr) {
            console.error("PDF download/parsing error:", pdfErr);
            admissionGuideText = "PDF 다운로드 또는 파싱 중 오류가 발생했습니다. 일반적인 입시 기준으로 분석합니다.";
        }
    }

    // 2. 프롬프트 구성
    const safeUserText = text.length > 20000 ? text.slice(0, 20000) + "...(생략됨)" : text;
    const userInfo = req.session && req.session.user 
        ? `학생 이름: ${req.session.user.name}, 학년: ${req.session.user.grade}` 
        : "학생 정보: 미로그인 사용자";

    let systemRole = `당신은 대한민국 최고의 입시 컨설턴트입니다. 
    제공된 [학생 생기부]와 [대학 모집요강(발췌본)]을 정밀 대조 분석하여 합격 전략을 제시해야 합니다.
    특히 모집요강에 명시된 평가 요소와 반영 비율을 근거로 학생을 냉철하게 평가하세요.`;

    let userInstruction = `
    [분석 대상]
    ${userInfo}
    - 목표 대학: ${targetUniv || "미정"}
    - 목표 학과: ${targetMajor || "미정"}
    - 목표 전형: ${targetType || "미정"}

    [대학 모집요강 데이터 (전형 관련 발췌)]
    ${admissionGuideText}

    [학생 생기부/성적 데이터]
    ${safeUserText}

    [요청 사항]
    위 모집요강 데이터를 바탕으로 학생이 목표 전형(${targetType})에 적합한지 분석해주세요.
    1. 모집요강에 명시된 '서류 평가 요소'별로 학생의 생기부를 매칭하여 점수를 예측해주세요.
    2. 해당 대학의 인재상과 학생의 활동이 얼마나 일치하는지 구체적인 키워드를 사용하여 설명해주세요.
    3. 합격 가능성을 높이기 위해 보완해야 할 점을 조언해주세요.
    4. 보통 교과의 경우 등급을 확인하세요.(예 : 1등급, 2등급, 3등급, 4등급, 5등급 등 어디에 해당하는지)
    `;

    // 3. OpenAI 호출 (수정된 부분)
    const response = await openai.chat.completions.create({
      model: 'gpt-4o', // [중요] gpt-5.1은 존재하지 않습니다. gpt-4o 또는 gpt-4-turbo로 변경하세요.
      messages: [
        { role: 'system', content: systemRole },
        { role: 'user', content: userInstruction }
      ],
      temperature: 0.7
    });

    // [중요] 응답 구조 확인 (안전 장치 추가)
    if (!response || !response.choices || !response.choices[0]) {
        console.error("OpenAI 응답 오류 (choices 없음):", response);
        return res.status(500).json({ error: "AI 서버로부터 올바른 응답을 받지 못했습니다." });
    }

    const message = response.choices[0].message;
    if (message.refusal) {
        return res.json({ result: `AI가 답변을 거절했습니다. 사유: ${message.refusal}` });
    }

    res.json({ result: message.content });

  } catch (err) {
    console.error('analyze error:', err);
    
    let errorMsg = 'AI 분석 중 서버 오류가 발생했습니다.';
    if (err.status === 401) errorMsg = 'OpenAI API 키가 잘못되었습니다.';
    else if (err.status === 429) errorMsg = '요청량이 너무 많습니다. (Rate Limit Exceeded)';
    
    res.status(500).json({ error: errorMsg, detail: err.message });
  }
});
app.post("/api/generate-essay-auto", async (req, res) => {
    try {
        const { pdfBase64, fileName, targetUniv, title } = req.body;
        const userId = req.session.user ? req.session.user.id : null;

        const pdfBuffer = Buffer.from(pdfBase64, "base64");
        const pdfData = await pdfParse(pdfBuffer);
        const text = pdfData.text.trim().slice(0, 15000);

        const prompt = `
        당신은 대한민국 대학 논술 출제위원입니다.
        제공된 텍스트(기출문제)를 분석하여 다음 단계를 수행하십시오.

        1. 이 내용이 '수리논술(Math)'인지 '인문논술(Humanities)'인지 판단하십시오.
        2. 제공된 텍스트를 바탕으로 **각 문제별 하나의 변형 문제**를 생성하십시오.
           - 대학별 출제 경향(${targetUniv || '일반'})을 반영하여 난이도를 조절하십시오.
        
        [중요 - 포맷팅 규칙]
        - 복잡한 수식(극한, 시그마, 분수, 인테그랄 등)은 반드시 블록 수식 형태인 '$$' 기호로 감싸십시오. (예: $$\\lim_{n \\to \\infty} \\sum_{k=1}^{n} \\frac{1}{k}$$)
        - 간단한 변수(n, x, f(x) 등)는 인라인 수식 형태인 '$' 기호로 감싸십시오. (예: $x$, $f(n)$)
        - 소문항(예: 1-1, 1-2)이 있다면, 반드시 각 소문항 앞에 줄바꿈 문자(\\n)를 두 번 넣어서 시각적으로 분리하십시오.
        
        3. **반드시 아래 JSON 형식으로만** 응답하십시오. (Markdown 코드 블록 없이 순수 JSON만 출력)

        {
            "type": "수리논술" 또는 "인문논술",
            "questions": [
                "문제 1의 전체 지문 및 질문 내용...",
                "문제 2의 전체 지문 및 질문 내용...",
                "문제 3의 전체 지문 및 질문 내용..."
            ]
        }

        [분석할 텍스트]:
        ${text}
        `;

        const response = await openai.chat.completions.create({
            model: "gpt-5.1",
            messages: [
                { role: "system", content: "Output strictly in JSON." },
                { role: "user", content: prompt }
            ],
            response_format: { type: "json_object" }
        });

        const jsonResult = JSON.parse(response.choices[0].message.content);

        let historyId = null;
        if (userId) {
            const savedTitle = title && title.trim() !== '' ? title : targetUniv;

            const [result] = await db.query(
                `INSERT INTO essay_history (user_id, target_univ, file_name, title, questions_json, created_at) 
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [userId, targetUniv || '미지정', fileName, savedTitle, JSON.stringify(jsonResult.questions)]
            );
            historyId = result.insertId;
        }

        res.json({
            success: true,
            type: jsonResult.type,
            questions: jsonResult.questions,
            historyId: historyId
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "생성 오류", detail: err.message });
    }
});

app.get('/api/public-exams', async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT id, target_univ, file_name, title, created_at, questions_json 
             FROM essay_history 
             WHERE questions_json IS NOT NULL 
             ORDER BY created_at DESC LIMIT 100`
        );
        res.json({ success: true, exams: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: "조회 실패" });
    }
});

app.post('/api/grade-essay', async (req, res) => {
    try {
        const { qaPairs, historyId, metaInfo, isCheating } = req.body; 
        const userId = req.session.user ? req.session.user.id : null;

        let gradingResult = "";

        if (isCheating) {
            gradingResult = `
                <div style="border: 2px solid #ef4444; background: #fef2f2; padding: 20px; border-radius: 12px; text-align: center;">
                    <h2 style="color: #ef4444; margin: 0 0 10px 0;">⚠️ 부정행위 감지 (0점)</h2>
                    <p style="color: #333;">시험 중 <strong>화면 이탈(탭 전환, 외부 클릭)</strong>이 감지되어 0점 처리되었습니다.</p>
                </div>
                <hr>
                <h3>[상세 기록]</h3>
                <ul>
                    <li>결과: <b>F (Fail)</b></li>
                    <li>사유: 보안 규정 위반</li>
                </ul>
            `;
        } else {
            let contentForAI = "학생 답안 채점 요청:\n\n";
            qaPairs.forEach((item, idx) => {
                contentForAI += `[Q${idx+1}] ${item.question}\n[A${idx+1}] ${item.answer}\n\n`;
            });

            const systemPrompt = `
                대한민국 대입 논술 채점위원입니다. HTML 리포트를 작성하세요.
                1. <h3>종합 등급 및 점수</h3> (예: A, 95/100)
                2. <hr>
                3. <h3>문항별 분석</h3>
                4. <h3>보완점 및 모범 답안 방향</h3>
                정중한 어조 사용.
            `;

            const response = await openai.chat.completions.create({
                model: "gpt-5.1",
                temperature: 0.3,
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: contentForAI }
                ]
            });
            gradingResult = response.choices[0].message.content;
        }

        const answersStr = JSON.stringify(qaPairs.map(q => q.answer));

        if (historyId) {
            await db.query(
                `UPDATE essay_history SET grading_result = ?, student_answers_json = ? WHERE id = ?`,
                [gradingResult, answersStr, historyId]
            );
        } else if (userId && metaInfo) {
            const questionsStr = JSON.stringify(qaPairs.map(q => q.question));
            await db.query(
                `INSERT INTO essay_history (user_id, target_univ, file_name, title, questions_json, student_answers_json, grading_result, created_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
                [userId, metaInfo.targetUniv, metaInfo.fileName, metaInfo.title, questionsStr, answersStr, gradingResult]
            );
        }

        res.json({ success: true, result: gradingResult });

    } catch (err) {
        console.error("채점 오류:", err);
        res.status(500).json({ error: "채점 처리 중 오류" });
    }
});

app.get('/api/essay-history', async (req, res) => {
    if (!req.session.user) return res.json({ success: false, message: "로그인 필요" });
    try {
        const [rows] = await db.query(
            `SELECT id, target_univ, file_name, title, created_at, grading_result, questions_json 
             FROM essay_history WHERE user_id = ? ORDER BY created_at DESC`,
            [req.session.user.id]
        );
        res.json({ success: true, history: rows });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 서버 실행 중 → http://localhost:${PORT}`);
});
