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
    logger.info(f"🚀 Запуск SunnyAreral Enterprise [Threads: {CONFIG.system['threads']}]")

    # 1. PARSING
    parser = LinkParser()
    nodes = await parser.fetch_and_parse()
    
    if not nodes:
        logger.error("❌ Не найдено ни одной валидной ссылки. Завершение.")
        sys.exit(0) # Exit 0 to prevent Action failure

    # 2. INSPECTION (Standard 5MB Test)
    inspector = Inspector()
    logger.info("🔬 Начинаем проверку (Sing-box Engine)...")
    
    tasks = [inspector.check_pipeline(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    
    # Filter Dead Nodes
    alive_nodes = [n for n in results if n is not None]
    
    logger.success(f"🏁 Первичная проверка завершена. Живых узлов: {len(alive_nodes)}")

    # 3. CHAMPION TEST (Heavy 25MB Test)
    if alive_nodes:
        # Sort to find the potential champion
        alive_nodes.sort(key=lambda x: x.speed, reverse=True)
        champion_node = alive_nodes[0]
        
        # Re-test the champion with heavy load
        new_speed = await inspector.engine.champion_run(champion_node)
        
        # Update speed only if test succeeded (otherwise keep old result)
        if new_speed > 0:
            champion_node.speed = new_speed
            # Re-sort because speed might have changed
            alive_nodes.sort(key=lambda x: x.speed, reverse=True)

    # 4. EXPORT
    if alive_nodes:
        Exporter.save_files(alive_nodes)
    else:
        logger.warning("⚠️ Нет рабочих прокси для сохранения.")

    # 5. REPORTING
    duration = time.perf_counter() - start_time
    await Exporter.send_telegram_report(len(nodes), alive_nodes, duration)
    
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
