
async function register(){

    const registerForm = document.getElementById("registerForm");
    registerForm.addEventListener('submit', async function (event) {

        event.preventDefault();
        console.log("Submit interceptado");


        const nameValue = document.querySelector('.input_name').value;
        const usernameValue = document.querySelector('.input_username').value;
        const roleValue = document.querySelector('#role').value;
        const passwordValue = document.querySelector('.input_password').value;
        const repeetPasswordValue = document.querySelector('.input_repeetPassword').value;
        const endpoint = '/auth/register';
            
        if(passwordValue != repeetPasswordValue){
            console.error("the passwords don't match");
            alert("The passwords don't match");
            return;

        }

        try{

            const response = await fetch(endpoint, {
                
            method: 'POST',
                headers: {
                'Content-Type': 'application/json'

                },
                credentials: 'include',
                body: JSON.stringify({
                    name: nameValue,
                    username: usernameValue,
                    password: passwordValue,
                    role: roleValue,
                    repeetPassword: repeetPasswordValue
                })

            });

            if(response.ok){
                const mensage = await response.text();

                alert("Authorized");
                
            }else{
                const errorMessage = await response.text();
                console.log(errorMessage);
            alert(errorMessage);
            }
        
        }catch(error){
            console.error("Connection refused ", error);
            alert("Connection refused");

        }

        
    });
    
}


register();