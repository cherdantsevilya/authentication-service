// Глобальные переменные
let currentUser = null;
let currentUsername = null;

// Функции для работы с формами
function toggleForms(showFormId) {
    const forms = ['loginForm', 'registerForm', 'totpForm', 'totpSetup', 'dashboard'];
    forms.forEach(formId => {
        document.getElementById(formId).style.display = formId === showFormId ? 'block' : 'none';
    });
}

// Обработка ошибок
function showError(message) {
    const modal = document.getElementById('errorModal');
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.textContent = message;
    modal.style.display = 'block';
}

function showSuccess(message) {
    const successModal = document.getElementById('success-modal');
    const successMessage = document.getElementById('success-message');
    successMessage.textContent = message;
    successModal.style.display = 'block';
}

function closeErrorModal() {
    document.getElementById('errorModal').style.display = 'none';
}

function closeSuccessModal() {
    const successModal = document.getElementById('success-modal');
    successModal.style.display = 'none';
}

// API calls
async function makeRequest(endpoint, method, data = null) {
    try {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        // Добавляем токен авторизации, если он есть
        if (currentUser && currentUser.token) {
            headers['Authorization'] = `Bearer ${currentUser.token}`;
        }

        console.log(`Making ${method} request to ${endpoint}`, {
            headers: headers,
            data: data
        });

        const response = await fetch(`/api/v1${endpoint}`, {
            method,
            headers,
            body: data ? JSON.stringify(data) : null
        });

        const responseData = await response.json();
        console.log(`Response from ${endpoint}:`, {
            status: response.status,
            data: responseData
        });
        
        if (!response.ok) {
            console.error('Request failed:', {
                status: response.status,
                response: responseData,
                endpoint: endpoint
            });
            throw new Error(responseData.error || 'Request failed');
        }

        return responseData;
    } catch (error) {
        console.error('Request error:', {
            error: error,
            endpoint: endpoint,
            method: method
        });
        throw error;
    }
}

// Функция для обновления таймера TOTP
function updateTOTPTimer() {
    const now = Math.floor(Date.now() / 1000);
    const period = 30; // TOTP период в секундах
    const remaining = period - (now % period);
    
    const timerElement = document.getElementById('totp-timer');
    if (timerElement) {
        timerElement.textContent = `Code expires in: ${remaining} seconds`;
        timerElement.style.color = remaining <= 5 ? '#ff0000' : '#666';
    }
}

// Показываем форму TOTP с таймером
function showTOTPForm() {
    toggleForms('totpForm');
    // Запускаем таймер
    updateTOTPTimer();
    setInterval(updateTOTPTimer, 1000);
    // Фокус на поле ввода
    document.getElementById('totp-code').focus();
}

// Добавляем обработчик для кнопки закрытия окна успеха
document.getElementById('close-success-btn').addEventListener('click', () => {
    closeSuccessModal();
});

// Обработчики форм
document.getElementById('login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        console.log('Attempting login for user:', username);
        const response = await makeRequest('/auth/login', 'POST', { username, password });
        console.log('Login response:', response);
        
        currentUsername = username;
        
        if (response.requires_totp) {
            console.log('2FA required, showing TOTP form');
            showTOTPForm();
        } else {
            console.log('Login successful, loading dashboard');
            currentUser = { token: response.token };
            await loadUserDashboard();
        }
    } catch (error) {
        console.error('Login failed:', error);
        showError(error.message || 'Login failed. Please try again.');
    }
});

document.getElementById('register').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const email = document.getElementById('reg-email').value;

    try {
        await makeRequest('/auth/register', 'POST', { username, password, email });
        showSuccess('Registration successful! Please login.');
        toggleForms('loginForm');
    } catch (error) {
        console.error('Registration failed:', error);
        showError(error.message || 'Registration failed. Please try again.');
    }
});

document.getElementById('totp').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('totp-code').value;

    try {
        console.log('Verifying TOTP code:', code, 'for user:', currentUsername);
        const response = await makeRequest('/auth/verify-totp', 'POST', {
            username: currentUsername,
            code: code.trim()
        });

        console.log('TOTP verification response:', response);

        if (response.token) {
            currentUser = { token: response.token };
            showSuccess('Successfully logged in with 2FA');
            await loadUserDashboard();
        } else {
            showError('Invalid TOTP code. Please try again.');
            document.getElementById('totp-code').value = '';
            document.getElementById('totp-code').focus();
        }
    } catch (error) {
        console.error('TOTP verification error details:', {
            message: error.message,
            stack: error.stack,
            currentUsername: currentUsername
        });
        showError('Invalid TOTP code. Please make sure you enter the current code.');
        document.getElementById('totp-code').value = '';
        document.getElementById('totp-code').focus();
    }
});

// Функции для работы с 2FA
async function setupTOTP() {
    try {
        const response = await makeRequest('/protected/setup-2fa', 'POST');
        console.log('Setup 2FA response:', response);
        
        const qrCode = document.getElementById('qrCode');
        const manualCode = document.getElementById('manualCode');
        
        console.log('QR Code URL:', response.qr_code_url);
        qrCode.src = response.qr_code_url;
        qrCode.alt = 'QR Code for 2FA setup';
        manualCode.textContent = response.manual_code;
        
        toggleForms('totpSetup');
    } catch (error) {
        console.error('Failed to setup 2FA:', error);
        showError('Failed to setup 2FA. Please try again.');
    }
}

async function completeTOTPSetup() {
    try {
        // Проверяем, что пользователь действительно настроил 2FA
        const code = prompt('Please enter the TOTP code from your authenticator app to verify setup:');
        if (!code) {
            showError('Please enter the TOTP code to complete setup');
            return;
        }

        console.log('Verifying TOTP code:', code, 'for user:', currentUsername);
        
        const response = await makeRequest('/auth/verify-totp', 'POST', {
            username: currentUsername,
            code: code.trim() // Убираем лишние пробелы
        });

        console.log('TOTP verification response:', response);

        if (response.token) {
            currentUser = { token: response.token };
            await loadUserDashboard();
        } else {
            showError('Invalid TOTP code. Please try again.');
        }
    } catch (error) {
        console.error('Failed to complete 2FA setup:', error);
        showError('Failed to verify 2FA setup. Please try again.');
    }
}

// Функции для работы с дашбордом
async function loadUserDashboard() {
    try {
        console.log('Loading user dashboard...');
        const userInfo = await makeRequest('/protected/me', 'GET');
        console.log('User info:', userInfo);

        if (!userInfo) {
            throw new Error('Failed to load user information');
        }

        document.getElementById('username-display').textContent = userInfo.username || 'Unknown';
        document.getElementById('user-email').textContent = userInfo.email || 'No email';
        document.getElementById('totp-status').textContent = userInfo.totp_enabled ? 'Enabled' : 'Disabled';
        
        // Показываем/скрываем кнопки в зависимости от статуса 2FA
        const setupButton = document.getElementById('setup-totp-btn');
        const disableButton = document.getElementById('disable-totp-btn');
        
        if (setupButton) setupButton.style.display = userInfo.totp_enabled ? 'none' : 'block';
        if (disableButton) disableButton.style.display = userInfo.totp_enabled ? 'block' : 'none';
        
        console.log('Dashboard loaded successfully');
        toggleForms('dashboard');
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        showError(error.message || 'Failed to load user information. Please try logging in again.');
        logout();
    }
}

function logout() {
    currentUser = null;
    currentUsername = null;
    toggleForms('loginForm');
}

async function disableTOTP() {
    const username = document.getElementById('username-display').textContent;
    
    if (!confirm('Are you sure you want to disable 2FA? This will make your account less secure.')) {
        return;
    }

    try {
        await makeRequest(`/admin/disable-2fa/${username}`, 'POST');
        showSuccess('Two-factor authentication has been disabled successfully');
        await loadUserDashboard(); // Перезагружаем дашборд для обновления статуса
    } catch (error) {
        console.error('Failed to disable 2FA:', error);
        showError(error.message || 'Failed to disable 2FA. Please try again.');
    }
}

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    toggleForms('loginForm');
});

// Add event listeners for success modal and disable TOTP
document.addEventListener('DOMContentLoaded', function() {
    // ... existing event listeners ...
    
    const closeSuccessBtn = document.getElementById('close-success-btn');
    if (closeSuccessBtn) {
        closeSuccessBtn.addEventListener('click', closeSuccessModal);
    }
    
    const disableTOTPBtn = document.getElementById('disable-totp-btn');
    if (disableTOTPBtn) {
        disableTOTPBtn.addEventListener('click', disableTOTP);
    }
}); 