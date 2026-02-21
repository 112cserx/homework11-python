import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==============================
# ЭТАП 1. Загрузка данных
# ==============================

df_raw = pd.read_json("botsv1.json")
df = pd.json_normalize(df_raw["result"])

print("\nКоличество строк:", len(df))
print("Количество колонок:", len(df.columns))


# ==============================
# ЭТАП 2. Анализ WinEventLog
# ==============================

print("\nРаспределение EventCode:")
print(df["EventCode"].value_counts())

suspicious_events = ["4624", "4625", "4688", "4689", "4703"]

df_suspicious = df[df["EventCode"].isin(suspicious_events)]

print("\nКоличество подозрительных событий:", len(df_suspicious))


# ==============================
# ЭТАП 2. DNS анализ
# ==============================

df_dns = df[df["EventCode"] == "DNS"]

print("\nDNS события:")
print(df_dns[["QueryName", "ClientIP"]])

dns_counts = df_dns["QueryName"].value_counts()

print("\nЧастота DNS запросов:")
print(dns_counts)


# ==============================
# ЭТАП 3. Визуализация
# ==============================

# --- График WinEventLog ---
top_win_events = df_suspicious["EventCode"].value_counts().head(10)

plt.figure(figsize=(8, 5))
sns.barplot(x=top_win_events.index, y=top_win_events.values)

plt.title("Top-10 подозрительных WinEventLog событий")
plt.xlabel("EventCode")
plt.ylabel("Количество")
plt.tight_layout()
plt.show()


# --- График DNS ---
if not dns_counts.empty:
    plt.figure(figsize=(8, 5))
    sns.barplot(x=dns_counts.index, y=dns_counts.values)

    plt.title("Подозрительные DNS запросы")
    plt.xlabel("Домен")
    plt.ylabel("Количество")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


# --- Объединённая визуализация ---
combined_counts = pd.concat([top_win_events, dns_counts])

plt.figure(figsize=(9, 5))
sns.barplot(x=combined_counts.index, y=combined_counts.values)

plt.title("Общая визуализация подозрительных событий")
plt.xlabel("Событие / Домен")
plt.ylabel("Количество")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
