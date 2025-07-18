// --- Central Translation Dictionary ---
const translations = {
    // -------------------------------------------------------------------
    // 全局和主导航 (index.html)
    // -------------------------------------------------------------------
    'pageTitle_main': { 'English': 'Knowledge Factory', 'Chinese Simplified': '知识库工厂' },
    'sidebar_qa_chunk': { 'English': 'Q&A Generation (By Chunk)', 'Chinese Simplified': '问答生成(按块)' },
    'sidebar_qa_page': { 'English': 'Q&A Generation (By Page)', 'Chinese Simplified': '问答生成(按页)' },
    'sidebar_qa_generation': {'English':'Q&A Generation', 'Chinese Simplified':'问答生成'},
    'sidebar_session': { 'English': 'Session Analysis', 'Chinese Simplified': '会话分析' },
    'footer_text': { 'English': '© 2025 Knowledge Base Factory | An auxiliary tool for knowledge base generation', 'Chinese Simplified': '© 2025 知识库工厂 | 知识库辅助生成工具' },

    // -------------------------------------------------------------------
    // 问答生成页 (qa-generation-*.html)
    // -------------------------------------------------------------------
    'pageTitle_qa': { 'English': 'Q&A Generation', 'Chinese Simplified': '问答生成' },
    // 表单标签
    'uploadLabel': { 'English': 'Upload Files', 'Chinese Simplified': '上传文件' },
    'docLangLabel': { 'English': 'Document Language', 'Chinese Simplified': '文档语言' },
    'langOptionEn': { 'English': 'English', 'Chinese Simplified': '英文' },
    'langOptionZh': { 'English': 'Chinese', 'Chinese Simplified': '中文' },
    'tenantLabel': { 'English': 'Select Tenant', 'Chinese Simplified': '租户选择' },
    'tenantPlaceholder': { 'English': '-- Please select Client ID --', 'Chinese Simplified': '-- 请选择Client ID --' },
    'bizLabel': { 'English': 'Select Business', 'Chinese Simplified': '业务选择' },
    'bizPlaceholder': { 'English': '-- Please select a business --', 'Chinese Simplified': '-- 请选择业务 --' },
    'prodLabel': { 'English': 'Select Product', 'Chinese Simplified': '产品选择' },
    'prodPlaceholder': { 'English': '-- Please select a business first --', 'Chinese Simplified': '-- 请先选择业务 --' },
    'taskTypeLabel': { 'English': 'Task Type', 'Chinese Simplified': '任务类型' },
    'taskTypeA': { 'English': 'Find answers based on questions (a)', 'Chinese Simplified': '根据问题找答案 (a)' },
    'questionListLabel': { 'English': 'Upload Question List (single column xlsx)', 'Chinese Simplified': '上传问题列表 (xlsx单列)' },
    'optionsLabel': { 'English': 'Options', 'Chinese Simplified': '操作选项' },
    'clearHistoryLabel': { 'English': 'Clear history before generation', 'Chinese Simplified': '生成前清除历史问答' },
    'reqTitle': { 'English': 'Q&A Generation Requirements', 'Chinese Simplified': '问答生成要求' },
    'reqPlaceholder': { 'English': 'Enter generation requirements...', 'Chinese Simplified': '请输入生成要求' },
    'generationMethodLabel': { 'English': 'Generation Method', 'Chinese Simplified': '生成方式' },
    'methodPageLabel': { 'English': 'By Page (More Context)', 'Chinese Simplified': '按页 (上下文更完整)' },
    'methodChunkLabel': { 'English': 'By Chunk (Simpler)', 'Chinese Simplified': '按块 (更简单)' },
    // 按钮
    'createKbButton': { 'English': 'Create Knowledge Base', 'Chinese Simplified': '创建知识库' },
    'generateButton': { 'English': 'Generate Q&A', 'Chinese Simplified': '生成问答' },
    'cancelButton': { 'English': 'Cancel Generation', 'Chinese Simplified': '取消生成' },
    'queryButton': { 'English': 'Query Q&A', 'Chinese Simplified': '查询问答' },
    'exportButton': { 'English': 'Export to CSV', 'Chinese Simplified': '导出为 CSV' },
    // 状态和表格
    'statusWaiting': { 'English': 'Waiting for action...', 'Chinese Simplified': '等待操作...' },
    'tableHeaderIndex': { 'English': 'No.', 'Chinese Simplified': '序号' },
    'tableHeaderQuestion': { 'English': 'Question', 'Chinese Simplified': '问题' },
    'tableHeaderAnswer': { 'English': 'Answer', 'Chinese Simplified': '答案' },
    'noDataToExport': { 'English': 'No data to export.', 'Chinese Simplified': '没有数据可供导出。' },

    // -------------------------------------------------------------------
    // 会话分析页 (session-analysis.html)
    // -------------------------------------------------------------------
    'pageTitle_session': { 'English': 'Session Analysis', 'Chinese Simplified': '会话分析' },
    // 表单标签
    'startTimeLabel': { 'English': 'Start Time', 'Chinese Simplified': '开始时间' },
    'endTimeLabel': { 'English': 'End Time', 'Chinese Simplified': '结束时间' },
    'sessionCountLabel': { 'English': 'Number of Sessions', 'Chinese Simplified': '会话数量' },
    // 按钮
    'analyzeButton': { 'English': 'Analyze Sessions', 'Chinese Simplified': '会话分析' },
    'cancelAnalysisButton': { 'English': 'Cancel Analysis', 'Chinese Simplified': '取消分析' },
    // 状态和表格
    'statusWaitingAnalysis': { 'English': 'Waiting for analysis...', 'Chinese Simplified': '等待分析...' },
    'tableHeaderSessionUrl': { 'English': 'Session URL', 'Chinese Simplified': '会话地址' },
    'tableHeaderCustomerQuery': { 'English': 'Customer Utterance', 'Chinese Simplified': '客户语句' },
    'tableHeaderStandardQuestion': { 'English': 'Standard Question', 'Chinese Simplified': '标准问题' },
    'tableHeaderNewQuestion': { 'English': 'New Question', 'Chinese Simplified': '新问题' },
    'tableHeaderAgentResponse': { 'English': 'Agent Utterance', 'Chinese Simplified': '坐席语句' },

    // 问题生成页面
    'sidebar_question_gen': { 'English': 'Question Generation', 'Chinese Simplified': '常见问题生成' },
    'pageTitle_question_gen': { 'English': 'Common Scenarios Question Generation', 'Chinese Simplified': '常见场景问题生成' },
    'qg_roleLabel': { 'English': 'Role', 'Chinese Simplified': '角色' },
    'qg_rolePlaceholder': { 'English': 'e.g., customer service agent, technical support', 'Chinese Simplified': '例如：客服、技术支持' },
    'qg_categoriesLabel': { 'English': 'Question Categories', 'Chinese Simplified': '问题场景分类' },
    'qg_categoriesPlaceholder': { 'English': 'e.g., questions about product features and pricing', 'Chinese Simplified': '例如：关于产品功能和价格的问题' },
    'qg_styleLabel': { 'English': 'Style (Optional)', 'Chinese Simplified': '风格 (选填)' },
    'qg_stylePlaceholder': { 'English': 'e.g., concise and direct', 'Chinese Simplified': '例如：简洁、直接' },
    'qg_numberLabel': { 'English': 'Number of Questions', 'Chinese Simplified': '问题数量' },
    'qg_generateButton': { 'English': 'Generate Questions', 'Chinese Simplified': '生成问题' },
    'qg_resultsTitle': { 'English': 'Generated Questions', 'Chinese Simplified': '生成的问题' },

    // -------------------------------------------------------------------
    // 生成要求文本
    // -------------------------------------------------------------------
    'generationRequirements': {
        'Chinese Simplified': `请先总结内容，提取内容的知识点，然后去生成问答，要保证语义完整。提问必须能在文档中找到答案。答案要完整。不要针对目录、概览、索引等无关内容提问。`,
        'English': `Please summarize the content first, extract key points, then generate Q&A, ensuring semantic completeness. Questions must have answers findable in the document, and answers should be comprehensive. Do not ask questions about irrelevant content such as tables of contents, overviews, or indexes.`
    }
};

/**
 * Applies translations to the page and any iframes.
 * This is the core function that makes the translation happen.
 * @param {string} lang - The language to switch to ('English' or 'Chinese Simplified').
 */
function setLanguage(lang) {
    if (!lang) return;

    // 1. Define the documents to translate. Start with the main document.
    const docsToTranslate = [document];
    const iframe = document.getElementById('content-iframe');
    // **Crucially, add the iframe's document if it exists and is accessible**
    if (iframe && iframe.contentDocument) {
        docsToTranslate.push(iframe.contentDocument);
    }

    // 2. Loop through each document (main page and iframe) and apply keys
    docsToTranslate.forEach(doc => {
        // Translate standard text elements
        doc.querySelectorAll('[data-translate-key]').forEach(element => {
            const key = element.getAttribute('data-translate-key');
            if (translations[key] && translations[key][lang]) {
                const textNode = element.querySelector('span') || element;
                textNode.textContent = translations[key][lang];
            }
        });

        // Translate placeholder text for inputs/textareas
        doc.querySelectorAll('[data-translate-key-placeholder]').forEach(element => {
            const key = element.getAttribute('data-translate-key-placeholder');
            if (translations[key] && translations[key][lang]) {
                element.placeholder = translations[key][lang];
            }
        });
    });

    // 3. Save the chosen language to localStorage. This is the single variable.
    localStorage.setItem('userLanguage', lang);
}

/**
 * Sets up the language switcher and ensures translations are applied on load.
 */
function initLanguageSwitcher() {
    const langToggle = document.getElementById('language-toggle');
    const iframe = document.getElementById('content-iframe');
    // Get the saved language or default to Chinese
    const savedLang = localStorage.getItem('userLanguage') || 'Chinese Simplified';

    if (langToggle) {
        // Set the switch to the correct position based on the saved language
        langToggle.checked = (savedLang === 'English');

        // Listen for clicks on the switch
        langToggle.addEventListener('change', (e) => {
            const newLang = e.target.checked ? 'English' : 'Chinese Simplified';
            setLanguage(newLang);
        });
    }

    // **This is the key fix:** Listen for when the iframe finishes loading its content.
    if (iframe) {
        iframe.addEventListener('load', () => {
            // When the iframe is loaded, apply the currently saved language to its content.
            const currentLang = localStorage.getItem('userLanguage') || 'Chinese Simplified';
            setLanguage(currentLang);
        });
    }

    // Apply the language to the main page immediately on load
    setLanguage(savedLang);
}

// Run the setup function once the main page's DOM is ready.
document.addEventListener('DOMContentLoaded', initLanguageSwitcher);