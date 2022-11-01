const inactivityTime = function () {
    var time;
    document.onload = resetTimer;
    document.onmousemove = resetTimer;
    document.onmousedown = resetTimer;
    document.ontouchstart = resetTimer;
    document.onclick = resetTimer;
    document.onkeydown = resetTimer;
    document.addEventListener('scroll', resetTimer, true);

    function logout() {
        window.location.href = 'timeout'
    }

    function resetTimer() {
        clearTimeout(time);
        time = setTimeout(logout, 60000)
    }
};
inactivityTime();