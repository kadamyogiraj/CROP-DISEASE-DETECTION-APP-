/**
 * PlantCare AI - i18n (Internationalization) Engine
 * Supports: English (en), Hindi (hi), Marathi (mr)
 * Usage: Add data-i18n="key.path" attributes to HTML elements.
 *        For placeholders: add data-i18n-placeholder="key.path"
 */

(function () {
    const SUPPORTED_LANGS = ['en', 'hi', 'mr'];
    const STORAGE_KEY = 'plantcare_lang';
    let _translations = {};
    let _currentLang = 'en';

    /** Resolve a dot-notation key from the translation object */
    function _get(key) {
        return key.split('.').reduce(function (obj, k) {
            return obj && obj[k] !== undefined ? obj[k] : null;
        }, _translations);
    }

    /** Replace all data-i18n elements with translated text */
    function _applyTranslations() {
        // Text content
        document.querySelectorAll('[data-i18n]').forEach(function (el) {
            var value = _get(el.getAttribute('data-i18n'));
            if (value !== null) el.textContent = value;
        });
        // Placeholder attributes (inputs/textareas)
        document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
            var value = _get(el.getAttribute('data-i18n-placeholder'));
            if (value !== null) el.placeholder = value;
        });
        // data-i18n-title for title attributes
        document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
            var value = _get(el.getAttribute('data-i18n-title'));
            if (value !== null) el.title = value;
        });
        // Update html lang attribute
        document.documentElement.lang = _currentLang;
    }

    /** Load a locale JSON file and apply it */
    async function _loadLanguage(lang) {
        if (!SUPPORTED_LANGS.includes(lang)) lang = 'en';
        _currentLang = lang;

        try {
            var response = await fetch('/static/locales/' + lang + '.json?v=1');
            if (!response.ok) throw new Error('Locale not found: ' + lang);
            _translations = await response.json();
            localStorage.setItem(STORAGE_KEY, lang);
            _applyTranslations();
        } catch (e) {
            console.error('[i18n] Failed to load language:', lang, e);
            // Fallback to English
            if (lang !== 'en') _loadLanguage('en');
        }
    }

    /** Public: switch language and optionally sync to server */
    async function setLanguage(lang, syncServer) {
        await _loadLanguage(lang);
        if (syncServer !== false) {
            try {
                await fetch('/api/language', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ lang: lang })
                });
            } catch (e) { /* ignore – server sync is best-effort */ }
        }
    }

    /** Public: translate a key programmatically */
    function t(key, fallback) {
        var v = _get(key);
        return v !== null ? v : (fallback || key);
    }

    /** Public: get current language code */
    function getLang() { return _currentLang; }

    // Expose globals
    window.setLanguage = setLanguage;
    window.t = t;
    window.getLang = getLang;

    // Auto-init: read saved preference and load on DOMContentLoaded
    var _initLang = localStorage.getItem(STORAGE_KEY) || 'en';

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { _loadLanguage(_initLang); });
    } else {
        _loadLanguage(_initLang);
    }
})();
