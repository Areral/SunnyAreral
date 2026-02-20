import asyncio
import time
import sys
from loguru import logger

from core.settings import CONFIG
from core.parser import LinkParser
from core.engine import Inspector
from core.exporter import Exporter

async def main():
    start_time = time.perf_counter()
    logger.info(f"🚀 Запуск SunnyAreral Enterprise v11 [Batch Mode]")

    # 1. PARSING
    parser = LinkParser()
    nodes = await parser.fetch_and_parse()
    
    if not nodes:
        logger.error("❌ Не найдено ни одной валидной ссылки.")
        sys.exit(0)

    # 2. INSPECTION (BATCH MODE)
    inspector = Inspector()
    logger.info("🔬 Начинаем пакетную проверку (Batch Engine)...")
    
    # Получаем живые узлы и телеметрию
    alive_nodes, error_stats = await inspector.process_all(nodes)
    
    logger.success(f"🏁 Проверка завершена. Живых узлов: {len(alive_nodes)}")

    # 3. CHAMPION TEST
    if alive_nodes:
        alive_nodes.sort(key=lambda x: x.speed, reverse=True)
        champion_node = alive_nodes[0]
        
        new_speed = await inspector.engine.champion_run(champion_node)
        if new_speed > 0:
            champion_node.speed = new_speed
            alive_nodes.sort(key=lambda x: x.speed, reverse=True)

    # 4. EXPORT
    if alive_nodes:
        Exporter.save_files(alive_nodes)
    else:
        logger.warning("⚠️ Нет рабочих прокси для сохранения.")

    # 5. REPORTING (with Telemetry)
    duration = time.perf_counter() - start_time
    await Exporter.send_telegram_report(len(nodes), alive_nodes, error_stats, duration)
    
    logger.info(f"✅ Система завершила работу за {duration:.2f} сек.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Остановка пользователем")
    except Exception as e:
        logger.critical(f"FATAL ERROR: {e}")
        sys.exit(1)
