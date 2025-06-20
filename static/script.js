document.addEventListener('DOMContentLoaded', function() {
    // Elementos del formulario
    const keyInput = document.getElementById('key');
    const messageInput = document.getElementById('message');
    const keyTypeRadios = document.querySelectorAll('input[name="key_type"]');
    const messageTypeRadios = document.querySelectorAll('input[name="message_type"]');
    const forms = document.querySelectorAll('form');

    // Guardar datos del formulario en sessionStorage
    function saveFormData(form) {
        const formData = new FormData(form);
        const data = {};
        formData.forEach((value, key) => {
            data[key] = value;
        });
        sessionStorage.setItem('formData', JSON.stringify(data));
    }

    // Cargar datos guardados
    function loadFormData() {
        const savedData = sessionStorage.getItem('formData');
        if (savedData) {
            const data = JSON.parse(savedData);

            // Restaurar valores de los radio buttons
            document.querySelector(`input[name="key_type"][value="${data.key_type}"]`).checked = true;
            document.querySelector(`input[name="message_type"][value="${data.message_type}"]`).checked = true;

            // Restaurar valores de los inputs
            keyInput.value = data.key || '';
            messageInput.value = data.message || '';

            // Aplicar validación según los valores cargados
            validateInputs();
        }
    }

    // Validar inputs según el tipo seleccionado
    function validateInputs() {
        const isHexKey = document.querySelector('input[name="key_type"]:checked').value === 'hex';
        const isHexMessage = document.querySelector('input[name="message_type"]:checked').value === 'hex';

        // Validación para la clave
        if (isHexKey) {
            keyInput.maxLength = 32;
            keyInput.pattern = '[0-9a-fA-F]{32}';
            keyInput.title = 'Debe contener exactamente 32 caracteres hexadecimales (0-9, a-f)';
        } else {
            keyInput.maxLength = 16;
            keyInput.pattern = '.{16}';
            keyInput.title = 'Debe contener exactamente 16 caracteres';
        }

        // Validación para el mensaje (solo hexadecimal debe tener longitud par)
        if (isHexMessage) {
            messageInput.pattern = '[0-9a-fA-F]+';
            messageInput.title = 'Solo caracteres hexadecimales (0-9, a-f)';
        } else {
            messageInput.removeAttribute('pattern');
            messageInput.title = '';
        }

        // Limpiar mensajes de error al cambiar
        const errorElements = document.querySelectorAll('.error-message');
        errorElements.forEach(el => el.remove());
    }

    // Mostrar errores bajo los inputs
    function showError(input, message) {
        // Eliminar errores previos
        const existingError = input.nextElementSibling;
        if (existingError && existingError.classList.contains('error-message')) {
            existingError.remove();
        }

        // Crear elemento de error
        const errorElement = document.createElement('div');
        errorElement.className = 'error-message text-danger mt-1';
        errorElement.textContent = message;
        input.insertAdjacentElement('afterend', errorElement);

        // Resaltar input con error
        input.classList.add('is-invalid');
    }

    // Validar antes de enviar
    function validateBeforeSubmit(e) {
        let isValid = true;
        const isHexKey = document.querySelector('input[name="key_type"]:checked').value === 'hex';
        const isHexMessage = document.querySelector('input[name="message_type"]:checked').value === 'hex';

        // Validar clave
        if (isHexKey) {
            if (!/^[0-9a-fA-F]{32}$/.test(keyInput.value)) {
                showError(keyInput, 'La clave debe tener exactamente 32 caracteres hexadecimales');
                isValid = false;
            }
        } else {
            if (keyInput.value.length !== 16) {
                showError(keyInput, 'La clave debe tener exactamente 16 caracteres');
                isValid = false;
            }
        }

        // Validar mensaje
        if (isHexMessage) {
            // if (!/^[0-9a-fA-F]+$/.test(messageInput.value)) {
            //     showError(messageInput, 'El mensaje solo puede contener caracteres hexadecimales (0-9, a-f)');
            //     isValid = false;
            // } else if (messageInput.value.length % 2 !== 0) {
            //     showError(messageInput, 'El mensaje hexadecimal debe tener una longitud par');
            //     isValid = false;
            // }
        }

        if (!isValid) {
            e.preventDefault();
            saveFormData(e.target); // Guardar datos a pesar del error
        }
    }

    //copiar el resultado
    function copyToClipboard(id) {
        const text = document.getElementById(id).textContent;
        navigator.clipboard.writeText(text)
            .then(() => alert(`${text} Copiado al portapapeles`))
            .catch(err => alert("Error al copiar: " + err));
    }

    // Descargar en un archivo de texto el resultado
    function downloadResult() {
        const original = document.getElementById('original_test').textContent.trim();
        const hex = document.getElementById('result_hex').textContent.trim();
        const text = document.getElementById('result_text').textContent.trim();

    const content =
`Texto original:
${original}

Resultado (Hexadecimal):
${hex}

Resultado (Texto):
${text}
`;

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "resultado_aes.txt";
    a.click();
}


    // Event listeners
    keyTypeRadios.forEach(radio => {
        radio.addEventListener('change', validateInputs);
    });

    messageTypeRadios.forEach(radio => {
        radio.addEventListener('change', validateInputs);
    });

    forms.forEach(form => {
        form.addEventListener('submit', validateBeforeSubmit);
        form.addEventListener('submit', function() {
            saveFormData(this);
        });
    });

    // Limitar caracteres no hexadecimales cuando corresponda
    if ( messageInput ) {
        messageInput.addEventListener('input', function() {
            const isHexMessage = document.querySelector('input[name="message_type"]:checked').value === 'hex';
            if (isHexMessage) {
                this.value = this.value.replace(/[^0-9a-fA-F]/g, '');
            }
        });
        // Cargar datos al iniciar
        loadFormData();
        validateInputs();
    }

    if ( keyInput ) {
        keyInput.addEventListener('input', function() {
            const isHexKey = document.querySelector('input[name="key_type"]:checked').value === 'hex';
            if (isHexKey) {
                this.value = this.value.replace(/[^0-9a-fA-F]/g, '');
            }
        });
    }

    let btnDownloadResult = document.getElementById('id_dwld_results');
    let btnCopyResult = document.getElementById('id_copy_result');

    if ( btnCopyResult ) {
        btnCopyResult.addEventListener('click', function () {
            copyToClipboard('result_hex');
        });
    }
    if ( btnDownloadResult ) {
        btnDownloadResult.addEventListener('click', downloadResult);
    }

});