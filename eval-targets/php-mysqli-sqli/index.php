<?php
// Minimal PHP/mysqli SQL injection target.
// Source: $_GET. Sink: mysqli::query.
// Joern's PHP frontend reports the sink at the `mysqli_query` call name.

$conn = new mysqli("localhost", "user", "pass", "db");

$id = $_GET["id"];
$sql = "SELECT name FROM users WHERE id = " . $id;
$result = $conn->query($sql);

while ($row = $result->fetch_assoc()) {
    echo $row["name"];
}
