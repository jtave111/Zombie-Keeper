document.querySelectorAll(".nav-toggle").forEach(toggle => {
    
    toggle.addEventListener("click", () => {

            const submenu = document.getElementById(toggle.dataset.target);
            submenu.classList.toggle("open");


        });

});