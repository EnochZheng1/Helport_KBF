// --- Central Translation Dictionary ---
const translations = {
    // Page Titles
    'pageTitle_qa': { 'English': 'Q&A Generation', 'Chinese Simplified': '问答生成' },
    'pageTitle_session': { 'English': 'Session Analysis', 'Chinese Simplified': '会话分析' },
    'pageTitle_main': { 'English': 'Knowledge Base Factory', 'Chinese Simplified': '知识库工厂' },

    // Labels & Placeholders
    'uploadLabel': { 'English': 'Upload PDF Files', 'Chinese Simplified': '上传 PDF 文件' },
    'docLangLabel': { 'English': 'Document Language', 'Chinese Simplified': '文档语言' },
    'tenantLabel': { 'English': 'Select Tenant', 'Chinese Simplified': '租户选择' },
    'bizLabel': { 'English': 'Select Business', 'Chinese Simplified': '业务选择' },
    'prodLabel': { 'English': 'Select Product', 'Chinese Simplified': '产品选择' },
    'taskTypeLabel': { 'English': 'Task Type', 'Chinese Simplified': '任务类型' },
    'taskTypeA': { 'English': 'Find answers based on questions (a)', 'Chinese Simplified': '根据问题找答案 (a)' },
    'optionsLabel': { 'English': 'Options', 'Chinese Simplified': '操作选项' },
    'clearHistoryLabel': { 'English': 'Clear history before generation', 'Chinese Simplified': '生成前清除历史问答' },
    'reqTitle': { 'English': 'Q&A Generation Requirements', 'Chinese Simplified': '问答生成要求' },
    'reqPlaceholder': { 'English': 'Enter generation requirements...', 'Chinese Simplified': '请输入生成要求' },

    // Buttons
    'createKbButton': { 'English': 'Create Knowledge Base', 'Chinese Simplified': '创建知识库' },
    'generateButton': {'English': 'Generate Q&A', 'Chinese Simplified': '生成问答' },
    'cancelButton': { 'English': 'Cancel Generation', 'Chinese Simplified': '取消生成' },
    'queryButton': { 'English': 'Query Q&A', 'Chinese Simplified': '查询问答' },
    'exportButton': { 'English': 'Export to CSV', 'Chinese Simplified': '导出为 CSV' },
    'analyzeButton': { 'English': 'Analyze Sessions', 'Chinese Simplified': '会话分析' },

    // Status & Table
    'statusWaiting': { 'English': 'Waiting for action...', 'Chinese Simplified': '等待操作...' },
    'tableHeaderIndex': { 'English': 'No.', 'Chinese Simplified': '序号' },
    'tableHeaderQuestion': { 'English': 'Question', 'Chinese Simplified': '问题' },
    'tableHeaderAnswer': { 'English': 'Answer', 'Chinese Simplified': '答案' },
    
    // Requirements Text
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