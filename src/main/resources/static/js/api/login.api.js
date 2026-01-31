

async function login() {

    const loginForm = document.getElementById("loginForm")

    loginForm.addEventListener('submit', async function(event){


        event.preventDefault();

        const usernameValue = document.querySelector('.input_username').value;  
        const passwordValue = document.querySelector('.input_password').value;

        const endpoint = '/auth/login';


        try{
            const response  = await fetch(endpoint, {
                method: 'POST',
                headers:{

                    'Content-Type':'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({
                    username: usernameValue,
                    password: passwordValue
                })

            });

            if(response.ok){

                const mensage = await response.text();
                console.log("Authorized", mensage);
                alert("Authorized");
            window.location.href = "/";

            }else{
                const errorMessage = await response.text();
                alert("Error");

            }

        }catch(error){
            console.error("Connection refused ", error);
            alert("Connection refused");
        
        }


    });
    

}


login();